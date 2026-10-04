#!/usr/bin/env python3
"""Train a PPO Red or Blue agent and compare it with the baselines.

Uses MaskablePPO: each turn the learner is told which moves are valid (derived
from its own view), which it needs to find the long multi-turn chain.

Needs: pip install gymnasium stable-baselines3 sb3-contrib

  python train_rl.py                                  # Red, 200k steps, then evaluate
  python train_rl.py --side blue --timesteps 400000   # train a learnable defender
  python train_rl.py --eval-only --model models/ppo_red.zip
  python run.py --red rl --rl-model models/ppo_red.zip   # watch a trained Red play
"""
from __future__ import annotations

import argparse
import os
import random
import statistics
import time

from sb3_contrib import MaskablePPO

from purple_sim.agents import HeuristicBlue, HeuristicRed, PolicyRed, SOCBlue
from purple_sim.agents.blue_rl import PolicyBlue
from purple_sim.agents.gym_env import (GymBlueEnv, GymRedEnv, load_policy_blue,
                                       load_policy_red)
from purple_sim.env.environment import Environment
from purple_sim.env.scenario import default_network
from purple_sim.orchestrator import Orchestrator, SimConfig

# Evaluation uses its own fixed seed block, so it is (effectively) on games the
# policy never trained on.
EVAL_SEED_BASE = 10 ** 6


def evaluate(make_red, make_blue, episodes: int) -> dict:
    wins, red_scores, blue_scores, coverages = 0, [], [], []
    for i in range(episodes):
        env = Environment(config={"seed": EVAL_SEED_BASE + i})
        report = Orchestrator(env, make_red(), make_blue(),
                              SimConfig(verbose=False, show_report=False)).run()
        wins += report["winner"] == "RED"
        red_scores.append(report["red_score"])
        blue_scores.append(report["blue_score"])
        coverages.append(report["coverage_pct"])
    return {"red_win": 100 * wins / episodes,
            "red_score": statistics.mean(red_scores),
            "blue_score": statistics.mean(blue_scores),
            "coverage": statistics.mean(coverages)}


def _default_model(side: str) -> str:
    return f"models/ppo_{side}.zip"


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--side", default="red", choices=["red", "blue"],
                   help="Which agent learns (the other side is a fixed heuristic).")
    p.add_argument("--timesteps", type=int, default=200_000)
    p.add_argument("--eval-episodes", type=int, default=300)
    p.add_argument("--model", default=None)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--eval-only", action="store_true")
    p.add_argument("--shaping", action="store_true",
                   help="Red only: potential-based milestone rewards (ADMIN, inside secure).")
    args = p.parse_args()
    model_path = args.model or _default_model(args.side)

    if not args.eval_only:
        env = (GymRedEnv(seed=args.seed, shaping=args.shaping) if args.side == "red"
               else GymBlueEnv(seed=args.seed))
        model = MaskablePPO("MlpPolicy", env, ent_coef=0.01, seed=args.seed,
                            device="cpu", verbose=0)
        start = time.time()
        model.learn(total_timesteps=args.timesteps)
        os.makedirs(os.path.dirname(model_path) or ".", exist_ok=True)
        model.save(model_path)
        print(f"Trained {args.side} {args.timesteps:,} steps in "
              f"{time.time() - start:.0f}s -> {model_path}")

    rng = random.Random(args.seed)

    def random_valid(obs, mask):
        return rng.choice([i for i, ok in enumerate(mask) if ok])

    if args.side == "red":
        ppo = load_policy_red(model_path)
        rnd = PolicyRed(random_valid, default_network(), "random")
        rows = (("random (valid)", lambda: rnd), ("heuristic", HeuristicRed),
                ("ppo", lambda: ppo))
        print(f"\nRed agents vs heuristic Blue, {args.eval_episodes} held-out games")
        print(f"{'Red agent':<14}{'Red win %':>11}{'Red score':>12}{'coverage %':>12}")
        for name, make in rows:
            r = evaluate(make, HeuristicBlue, args.eval_episodes)
            print(f"{name:<14}{r['red_win']:>11.1f}{r['red_score']:>12.1f}{r['coverage']:>12.1f}")
        print("(lower coverage = stealthier Red)")
    else:
        ppo = load_policy_blue(model_path)
        rows = (("heuristic", HeuristicBlue), ("soc", SOCBlue), ("ppo", lambda: ppo))
        print(f"\nBlue defenders vs heuristic Red, {args.eval_episodes} held-out games")
        print(f"{'Blue agent':<14}{'Blue win %':>11}{'Blue score':>12}{'coverage %':>12}")
        for name, make in rows:
            r = evaluate(HeuristicRed, make, args.eval_episodes)
            print(f"{name:<14}{100 - r['red_win']:>11.1f}{r['blue_score']:>12.1f}"
                  f"{r['coverage']:>12.1f}")
        print("(Blue win % = share of games Red failed to exfiltrate; Blue score "
              "penalises downtime and false positives, so a scorched-earth win scores low)")


if __name__ == "__main__":
    main()
