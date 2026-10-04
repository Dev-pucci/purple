"""Command-line entry point.

Examples
--------
  python -m purple_sim.cli                         # heuristic vs heuristic
  python -m purple_sim.cli --red llm --blue llm    # mock-LLM both sides (offline)
  python -m purple_sim.cli --red llm --live        # real Claude Red (needs API key)
  python -m purple_sim.cli --episodes 20 --quiet   # batch run, averaged coverage
  python -m purple_sim.cli --rl-demo               # random RL agent on the gym env
  python -m purple_sim.cli --red rl --rl-model models/ppo_red.zip  # trained PPO Red
  python -m purple_sim.cli --analyze --scenario enterprise  # blind-spot map for a network
"""
from __future__ import annotations

import argparse

from .agents import make_blue, make_red
from .agents.rl_interface import PurpleRedEnv, RandomRLAgent, train_notes
from .env.environment import Environment
from .env.scenario import SCENARIOS
from .orchestrator import Orchestrator, SimConfig
from .stats import mean_pm, pct_ci


def _report_fallbacks(args, agents_turns) -> None:
    """With --live, say how many turns the LLM didn't actually decide."""
    if not args.live:
        return
    for label, agents, turns in agents_turns:
        fell_back = sum(getattr(a, "fallbacks", 0) for a in agents)
        if fell_back:
            print(f"[llm] {label}: {fell_back}/{turns} turns fell back to the heuristic brain.")


def _env(args, seed: int) -> Environment:
    return Environment(config={"seed": seed, "scenario": args.scenario})


_policy_cache: dict = {}


def _make_red(args):
    if args.red != "rl":
        return make_red(args.red, mock=not args.live)
    key = ("red", args.rl_model)
    if key not in _policy_cache:  # load the model once per run
        from .agents.gym_env import load_policy_red  # needs gymnasium + stable-baselines3
        _policy_cache[key] = load_policy_red(args.rl_model)
    return _policy_cache[key]


def _make_blue(args):
    if args.blue != "rl":
        return make_blue(args.blue, mock=not args.live)
    key = ("blue", args.rl_blue_model)
    if key not in _policy_cache:
        from .agents.gym_env import load_policy_blue
        _policy_cache[key] = load_policy_blue(args.rl_blue_model)
    return _policy_cache[key]


def _single(args) -> dict:
    env = _env(args, args.seed)
    red = _make_red(args)
    blue = _make_blue(args)
    orch = Orchestrator(env, red, blue,
                        SimConfig(verbose=not args.quiet, color=not args.no_color,
                                  show_report=True))
    report = orch.run()
    _report_fallbacks(args, [("Red", [red], env.step_count),
                             ("Blue", [blue], env.step_count)])
    return report


def _batch(args) -> None:
    coverages, red_scores, blue_scores, red_wins, blue_wins = [], [], [], 0, 0
    reds, blues, turns = [], [], 0
    for i in range(args.episodes):
        env = _env(args, args.seed + i)
        red = _make_red(args)
        blue = _make_blue(args)
        report = Orchestrator(env, red, blue,
                              SimConfig(verbose=False, show_report=False)).run()
        reds.append(red)
        blues.append(blue)
        turns += env.step_count
        coverages.append(report["coverage_pct"])
        red_scores.append(report["red_score"])
        blue_scores.append(report["blue_score"])
        if report["winner"] == "RED":
            red_wins += 1
        else:
            blue_wins += 1
    n = args.episodes
    print(f"\n=== BATCH: {n} episodes, {args.scenario} scenario "
          f"({args.red} Red vs {args.blue} Blue) ===")
    print(f"Red win rate:  {pct_ci(red_wins, n)}   (95% CI)")
    print(f"Blue win rate: {pct_ci(blue_wins, n)}")
    print(f"Mean scores:   Red {mean_pm(red_scores)}   Blue {mean_pm(blue_scores)}")
    print(f"Mean coverage: {mean_pm(coverages)}%")
    _report_fallbacks(args, [("Red", reds, turns), ("Blue", blues, turns)])


def _analyze(args) -> None:
    """Aggregate a Purple blind-spot map over many games: for each host and each
    technique, how often Red's real attack steps there were detected + responded to."""
    from collections import defaultdict
    episodes = max(args.episodes, 50)
    by_host = defaultdict(lambda: [0, 0])       # node -> [executed, detected]
    by_tech = defaultdict(lambda: [0, 0])
    red_wins = 0
    for i in range(episodes):
        env = _env(args, args.seed + i)
        report = Orchestrator(env, _make_red(args), _make_blue(args),
                              SimConfig(verbose=False, show_report=False)).run()
        red_wins += report["winner"] == "RED"
        for row in report["coverage_rows"]:
            for table, key in ((by_host, row["node"]), (by_tech, row["technique"])):
                table[key][0] += 1
                table[key][1] += int(row["detected"])

    def fmt(table, title, label):
        print(f"\n{title}")
        print(f"  {label:<20}{'attack steps':>13}{'detected':>10}{'coverage':>10}")
        for key in sorted(table, key=lambda k: table[k][1] / max(table[k][0], 1)):
            ex, det = table[key]
            flag = "  <-- blind spot" if ex >= 5 and det / ex < 0.25 else ""
            print(f"  {key:<20}{ex:>13}{det:>10}{det / ex * 100:>9.0f}%{flag}")

    print(f"=== BLIND-SPOT MAP: {episodes} games on the {args.scenario} network "
          f"({args.red} Red vs {args.blue} Blue) ===")
    print(f"Red win rate: {red_wins / episodes * 100:.0f}%")
    fmt(by_host, "By host - where attacks land without a response:", "host")
    fmt(by_tech, "By technique - which ATT&CK steps slip through:", "technique")


def _rl_demo(args) -> None:
    env = PurpleRedEnv(seed=args.seed)
    agent = RandomRLAgent(env, seed=args.seed)
    obs = env.reset()
    total = 0.0
    done = False
    while not done:
        action = agent.act(obs)
        obs, reward, done, info = env.step(action)
        total += reward
    print("=== RL DEMO (random Red agent vs heuristic Blue) ===")
    print(f"Episode return: {total:.1f}   winner: {info['winner']}   "
          f"obs_dim={env.obs_dim}   actions={env.action_space_n}")
    print("\n" + train_notes())


def main(argv=None) -> None:
    p = argparse.ArgumentParser(description="Purple Team Red-vs-Blue simulation.")
    p.add_argument("--red", default="heuristic", choices=["heuristic", "llm", "rl"])
    p.add_argument("--rl-model", default="models/ppo_red.zip",
                   help="Trained PPO model for --red rl (see train_rl.py).")
    p.add_argument("--blue", default="heuristic", choices=["heuristic", "soc", "llm", "rl"])
    p.add_argument("--rl-blue-model", default="models/ppo_blue.zip",
                   help="Trained model for --blue rl (see train_rl.py --side blue).")
    p.add_argument("--live", action="store_true",
                   help="Use the real Claude API for LLM agents (needs ANTHROPIC_API_KEY).")
    p.add_argument("--episodes", type=int, default=1, help="Run N games and average.")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--scenario", default="default", choices=list(SCENARIOS),
                   help="'random' builds a different seeded network per episode.")
    p.add_argument("--quiet", action="store_true", help="Suppress per-turn trace.")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--rl-demo", action="store_true", help="Run the Gym-style RL demo.")
    p.add_argument("--analyze", action="store_true",
                   help="Aggregate a per-host / per-technique blind-spot map over many games.")
    args = p.parse_args(argv)
    if "rl" in (args.red, args.blue) and args.scenario != "default":
        p.error("--red/--blue rl are trained on the default network; use --scenario default.")

    if args.rl_demo:
        _rl_demo(args)
    elif args.analyze:
        _analyze(args)
    elif args.episodes > 1:
        _batch(args)
    else:
        _single(args)


if __name__ == "__main__":
    main()
