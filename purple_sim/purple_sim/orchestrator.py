"""The orchestrator: runs the adversarial turn loop and prints a trace."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .agents.base import BlueAgent, RedAgent
from .env.environment import Environment
from .scoring.scorer import Scorer

RED = "\033[91m"
BLUE = "\033[94m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


@dataclass
class SimConfig:
    verbose: bool = True        # per-turn trace
    color: bool = True
    show_report: bool = True    # final report (independent of the turn trace)


class Orchestrator:
    def __init__(self, env: Environment, red: RedAgent, blue: BlueAgent,
                 config: Optional[SimConfig] = None):
        self.env = env
        self.red = red
        self.blue = blue
        self.config = config or SimConfig()
        self.scorer = Scorer()

    def _c(self, text: str, color: str) -> str:
        if not self.config.color:
            return text
        return f"{color}{text}{RESET}"

    def run(self) -> dict:
        self.red.reset()
        self.blue.reset()
        if self.config.verbose:
            jewel = self.env.crown_jewel()
            print(self._c("\n=== PURPLE SIM: Red vs Blue ===", BOLD))
            print(f"Network: {', '.join(self.env.nodes)}  |  crown jewel: {jewel}  "
                  f"|  max steps: {self.env.max_steps}\n")

        while not self.env.done:
            red_action = self.red.act(self.env.red_view())
            # Blue is passed as a policy so it decides after Red's move resolves
            # and this step's telemetry is released.
            result = self.env.step(red_action, self.blue.act)
            if self.config.verbose:
                self._print_turn(result)

        report = self.scorer.final_report(self.env)
        if self.config.show_report:
            self._print_report(report)
        return report

    def _print_turn(self, result) -> None:
        print(self._c(f"--- Turn {result.step} ---", DIM))
        print(self._c(f"  RED  {result.red_action}", RED))
        print(f"       {DIM}{result.red_outcome}{RESET}"
              if self.config.color else f"       {result.red_outcome}")
        print(self._c(f"  BLUE {result.blue_action}", BLUE))
        print(f"       {DIM}{result.blue_outcome}{RESET}"
              if self.config.color else f"       {result.blue_outcome}")
        if result.new_events:
            kinds = ", ".join(f"{e.kind}@{e.node}" for e in result.new_events)
            print(f"       {DIM}telemetry now visible: {kinds}{RESET}"
                  if self.config.color else f"       telemetry now visible: {kinds}")
        print()

    def _print_report(self, report: dict) -> None:
        print(self._c("=== FINAL REPORT ===", BOLD))
        win_color = RED if report["winner"] == "RED" else BLUE
        print(f"Winner: {self._c(report['winner'], win_color)}  "
              f"({report['termination_reason']})")
        print(f"Steps: {report['steps']}   "
              f"Red score: {report['red_score']}   Blue score: {report['blue_score']}   "
              f"(containment TP={report['true_positives']} FP={report['false_positives']})")
        print(f"Exfiltrated: {report['exfiltrated']}")
        print()
        print(self._c("Purple coverage (what Red did vs what Blue caught):", BOLD))
        mttr = report["mean_time_to_respond"]
        mttr_txt = f"  |  mean time-to-respond {mttr:.1f} steps" if mttr is not None else ""
        print(f"  {report['attack_steps_detected']}/{report['attack_steps']} "
              f"attack steps detected  ->  coverage {report['coverage_pct']:.1f}%{mttr_txt}")
        for row in report["coverage_rows"]:
            mark = "DETECTED " if row["detected"] else "MISSED   "
            mcolor = BLUE if row["detected"] else RED
            seen = f"seen@{row['seen_at']}" if row["in_telemetry"] else "unseen"
            acted = f"response@{row['response_step']}" if row["blue_acted"] else "no response"
            print(f"    {self._c(mark, mcolor)} step {row['step']:>2}  "
                  f"{row['action']:<13} {row['node']:<12} "
                  f"[{row['technique']}]  {seen}, {acted}")
        if report["technique_coverage"]:
            print("  by technique: " + ", ".join(
                f"{t} {c['detected']}/{c['executed']}"
                for t, c in sorted(report["technique_coverage"].items())))
        print()
