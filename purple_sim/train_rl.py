#!/usr/bin/env python3
"""Train a PPO Red agent against the heuristic Blue and compare it with the baselines.

Uses MaskablePPO: each turn the agent is told which moves are valid (derived
from Red's own view), which it needs to find the multi-turn exfiltration.

Needs: pip install gymnasium stable-baselines3 sb3-contrib

  python train_rl.py                                  # 200k steps, then evaluate
  python train_rl.py --timesteps 50000 --eval-episodes 100
  python train_rl.py --eval-only                      # re-evaluate the saved model
  python run.py --red rl --rl-model models/ppo_red.zip   # watch it play
"""
from __future__ import annotations

import argparse
import os
import random
import statistics
import time

from sb3_contrib import MaskablePPO

from purple_sim.agents import HeuristicBlue, HeuristicRed, PolicyRed
from purple_sim.agents.gym_env import GymRedEnv, load_policy_red
from purple_sim.env.environment import Environment
from purple_sim.env.scenario import default_network
from purple_sim.orchestrator import Orchestrator, SimConfig

# Training seeds are drawn at random from [0, 2**31); evaluation uses its own
# fixed block, so the comparison is (effectively) on games PPO never saw.
EVAL_SEED_BASE = 10 ** 6


def evaluate(make_red, episodes: int) -> dict:
    wins, red_scores, coverages = 0, [], []
    for i in range(episodes):
        env = Environment(config={"seed": EVAL_SEED_BASE + i})
        report = Orchestrator(env, make_red(), HeuristicBlue(),
                              SimConfig(verbose=False, show_report=False)).run()
        wins += report["winner"] == "RED"
        red_scores.append(report["red_score"])
        coverages.append(report["coverage_pct"])
    return {"win_rate": 100 * wins / episodes,
            "red_score": statistics.mean(red_scores),
            "coverage": statistics.mean(coverages)}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--timesteps", type=int, default=200_000)
    p.add_argument("--eval-episodes", type=int, default=300)
    p.add_argument("--model", default="models/ppo_red.zip")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--eval-only", action="store_true")
    p.add_argument("--shaping", action="store_true",
                   help="Add potential-based milestone rewards (ADMIN, inside secure).")
    args = p.parse_args()

    if not args.eval_only:
        env = GymRedEnv(seed=args.seed, shaping=args.shaping)
        model = MaskablePPO("MlpPolicy", env, ent_coef=0.01, seed=args.seed,
                            device="cpu", verbose=0)
        start = time.time()
        model.learn(total_timesteps=args.timesteps)
        os.makedirs(os.path.dirname(args.model) or ".", exist_ok=True)
        model.save(args.model)
        print(f"Trained {args.timesteps:,} steps in {time.time() - start:.0f}s -> {args.model}")

    ppo_red = load_policy_red(args.model)
    rng = random.Random(args.seed)

    def random_valid(obs, mask):
        return rng.choice([i for i, ok in enumerate(mask) if ok])

    random_red = PolicyRed(random_valid, default_network(), "random")

    print(f"\nRed agents vs heuristic Blue, default network, {args.eval_episodes} held-out games")
    print(f"{'Red agent':<14} {'Red win %':>9} {'mean Red score':>15} {'Blue coverage %':>16}")
    for name, make in (("random (valid)", lambda: random_red), ("heuristic", HeuristicRed),
                       ("ppo", lambda: ppo_red)):
        r = evaluate(make, args.eval_episodes)
        print(f"{name:<14} {r['win_rate']:>9.1f} {r['red_score']:>15.1f} {r['coverage']:>16.1f}")
    print("(lower Blue coverage = stealthier Red)")


if __name__ == "__main__":
    main()
