#!/usr/bin/env python3
"""Reproduce the studies in ANALYSIS.md (zero dependencies).

  python experiments.py                 # run them all (a few hundred games each)
  python experiments.py --study posture --episodes 200
  python experiments.py --study defenders --scenario enterprise
  python experiments.py --study sensitivity   # the enterprise intervention sweep

Every number in ANALYSIS.md comes from here, so the findings are checkable
rather than taken on faith. Uses the scripted agents only (no RL deps); point
--blue at soc/heuristic to compare defenders.
"""
from __future__ import annotations

import argparse
import statistics
from collections import defaultdict

from purple_sim.agents.heuristic import HeuristicBlue, HeuristicRed
from purple_sim.agents.soc import AdaptiveBlue, SOCBlue
from purple_sim.env.environment import Environment
from purple_sim.env.models import Sensor
from purple_sim.env.scenario import FIREWALL, make_network
from purple_sim.orchestrator import Orchestrator, SimConfig
from purple_sim.stats import compare_proportions, mean_pm, pct_ci

BLUES = {"heuristic": HeuristicBlue, "soc": SOCBlue, "adaptive": AdaptiveBlue}
SEED_BASE = 5000


def play(scenario, blue_cls, n, mutate=None, cfg_extra=None):
    """Run n games of HeuristicRed vs blue_cls on a scenario; return aggregate stats."""
    wins, covs, blues = 0, [], []
    host = defaultdict(lambda: [0, 0])
    tech = defaultdict(lambda: [0, 0])
    for i in range(n):
        net = make_network(scenario, SEED_BASE + i)
        if mutate:
            mutate(net)
        cfg = {"seed": SEED_BASE + i, "scenario": scenario}
        if cfg_extra:
            cfg.update(cfg_extra)
        # A mutated network must be passed explicitly (with the firewall).
        env = (Environment(network=net, firewall=FIREWALL, config=cfg) if mutate
               else Environment(config=cfg))
        rep = Orchestrator(env, HeuristicRed(), blue_cls(),
                           SimConfig(verbose=False, show_report=False)).run()
        wins += rep["winner"] == "RED"
        covs.append(rep["coverage_pct"])
        blues.append(rep["blue_score"])
        for row in rep["coverage_rows"]:
            host[row["node"]][0] += 1
            host[row["node"]][1] += int(row["detected"])
            tech[row["technique"]][0] += 1
            tech[row["technique"]][1] += int(row["detected"])
    return {"wins": wins, "n": n, "red_win": 100 * wins / n, "coverages": covs,
            "blue_scores": blues, "host": host, "tech": tech}


def _cov(table, key):
    ex, det = table[key]
    return 100 * det / ex if ex else float("nan")


def study_defenders(args):
    print(f"\n# Defenders on the {args.scenario} network ({args.episodes} games each)")
    print(f"{'defender':<12}{'Red win % [95% CI]':>22}{'Blue score':>16}{'coverage %':>16}")
    results = {}
    for name, cls in BLUES.items():
        r = play(args.scenario, cls, args.episodes)
        results[name] = r
        print(f"{name:<12}{pct_ci(r['wins'], r['n']):>22}{mean_pm(r['blue_scores']):>16}"
              f"{mean_pm(r['coverages']):>16}")
    h, s = results["heuristic"], results["soc"]
    cmp = compare_proportions(h["wins"], h["n"], s["wins"], s["n"])
    verdict = "significant" if cmp.significant else "NOT significant (overlapping)"
    print(f"  soc vs heuristic Red-win difference: {100 * cmp.diff:+.0f} pts "
          f"[{100 * cmp.lo:+.0f}, {100 * cmp.hi:+.0f}] - {verdict}")


def study_posture(args):
    print(f"\n# Posture: same defender (soc), different architecture ({args.episodes} games)")
    print(f"{'network':<12}{'Red win % [95% CI]':>22}{'Blue score':>16}{'coverage %':>16}")
    for scenario in ("enterprise", "flat"):
        r = play(scenario, SOCBlue, args.episodes)
        print(f"{scenario:<12}{pct_ci(r['wins'], r['n']):>22}{mean_pm(r['blue_scores']):>16}"
              f"{mean_pm(r['coverages']):>16}")


def study_sensitivity(args):
    def edr_workstations(net):
        for n in ("workstation_eng", "workstation_hr"):
            if n in net:
                net[n].sensors[Sensor.ENDPOINT] = 0.7

    def all_edr(net):
        edr_workstations(net)
        if "file_server" in net:
            net["file_server"].sensors[Sensor.ENDPOINT] = 0.8

    rows = [
        ("baseline", None, None),
        ("+EDR on workstations", edr_workstations, None),
        ("faster logs (latency 1)", None, {"telemetry_latency": (1, 1)}),
        ("bigger SOC (budget 80)", None, {"analyst_budget": 80}),
        ("everything combined", all_edr, {"telemetry_latency": (1, 1), "analyst_budget": 80}),
    ]
    blue_cls = BLUES[args.blue]
    print(f"\n# Sensitivity on enterprise, {args.blue} defender ({args.episodes} games each)")
    print(f"{'intervention':<26}{'Red win % [95% CI]':>22}{'coverage %':>12}{'workstn %':>11}")
    for name, mut, cfg in rows:
        r = play("enterprise", blue_cls, args.episodes, mutate=mut, cfg_extra=cfg)
        ws = statistics.mean([_cov(r["host"], "workstation_eng"),
                              _cov(r["host"], "workstation_hr")])
        print(f"{name:<26}{pct_ci(r['wins'], r['n']):>22}"
              f"{statistics.mean(r['coverages']):>12.1f}{ws:>11.0f}")


def write_html(args):
    """Run the defender comparison + blind-spot map and write an HTML report."""
    from purple_sim.report import build_report
    from purple_sim.stats import pct_ci
    defenders = []
    best = None
    for name, cls in BLUES.items():
        r = play(args.scenario, cls, args.episodes)
        defenders.append({"name": name, "red_win": r["red_win"],
                          "red_win_label": pct_ci(r["wins"], r["n"]),
                          "blue_score": statistics.mean(r["blue_scores"]),
                          "coverage": statistics.mean(r["coverages"])})
        if best is None or r["red_win"] < best[0]:
            best = (r["red_win"], name, r)
    _, best_name, best_r = best
    blind = sorted(((h, ex, det) for h, (ex, det) in best_r["host"].items()),
                   key=lambda t: (t[2] / t[1] if t[1] else 0))
    findings = [
        f"Best defender here: '{best_name}' holds the attacker to "
        f"{best_r['red_win']:.0f}% wins.",
        "Hosts flagged 'blind spot' see real attacks but rarely trigger a response "
        "- usually a sensor gap or a host off the attack path.",
        "Detection speed and the right controls (deception, identity hygiene) move "
        "the outcome more than sensor or analyst volume - see ANALYSIS.md.",
    ]
    html_text = build_report(f"purple_sim - {args.scenario} assessment", args.scenario,
                             defenders, blind, findings, args.episodes)
    with open(args.html, "w", encoding="utf-8") as fh:
        fh.write(html_text)
    print(f"Wrote HTML report -> {args.html}")


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--study", default="all",
                   choices=["all", "defenders", "posture", "sensitivity"])
    p.add_argument("--scenario", default="enterprise")
    p.add_argument("--blue", default="soc", choices=list(BLUES))
    p.add_argument("--episodes", type=int, default=300)
    p.add_argument("--html", help="Write a shareable HTML report to this path instead of text.")
    args = p.parse_args()
    if args.html:
        write_html(args)
        return
    if args.study in ("all", "defenders"):
        study_defenders(args)
    if args.study in ("all", "posture"):
        study_posture(args)
    if args.study in ("all", "sensitivity"):
        study_sensitivity(args)


if __name__ == "__main__":
    main()
