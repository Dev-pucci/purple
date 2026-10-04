"""Scoring: separate Red and Blue scores, plus a Purple coverage report.

Design intent:
  - Red is rewarded for footholds (by node value), heavily for exfiltration, and
    for dwelling undetected (stealth).
  - Blue is rewarded for containing nodes that were *actually compromised at
    the moment it acted* (true positives), penalised for containing healthy
    nodes (false positives), and charged for every node-step of downtime
    (isolated or re-imaging). No-op actions earn nothing either way.
  - Purple coverage = of the attack steps Red actually executed, how many
    produced a genuine telemetry event that Blue then responded to (isolate or
    restore that host, or patch it while still clean) at or after the moment
    the event became visible. This is the real deliverable: a map of detection blind spots,
    correlated the honest way (ground truth vs what Blue saw), not Blue grading
    its own homework.

All ground truth comes from fields the Environment records on each StepResult.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from ..env.environment import Environment


class Scorer:
    EXFIL_BONUS = 50
    FOOTHOLD_WEIGHT = 5       # times node.value
    STEALTH_PER_STEP = 1      # per foothold, per step it stays undetected
    TRUE_POSITIVE_REWARD = 10 # Blue contains a node compromised at that moment
    FALSE_POSITIVE_PENALTY = 6
    DOWNTIME_PENALTY = 1      # per node, per step spent isolated, re-imaging or patching

    CONTAINMENT = ("ISOLATE", "RESTORE")
    RESPONSES = ("ISOLATE", "RESTORE", "PATCH")
    MATERIAL = ("EXPLOIT", "LATERAL_MOVE", "EXFILTRATE")

    def score_state(self, env: Environment) -> Dict[str, int]:
        """Cheap incremental score of the current ground-truth state (for RL)."""
        red = 0
        for node in env.nodes.values():
            if node.compromised:
                red += self.FOOTHOLD_WEIGHT * node.value
        if env.red_exfiltrated:
            red += self.EXFIL_BONUS
        return {"red": red, "blue": -red}

    def final_report(self, env: Environment) -> Dict[str, object]:
        """Full end-of-game scoring + Purple coverage, from env.history."""
        history = env.history

        # --- Red scoring --------------------------------------------------------
        compromised_ever = {r.red_compromised for r in history if r.red_compromised}
        red_score = sum(self.FOOTHOLD_WEIGHT * env.nodes[n].value for n in compromised_ever)
        red_score += self.STEALTH_PER_STEP * sum(r.undetected_footholds for r in history)
        if env.red_exfiltrated:
            red_score += self.EXFIL_BONUS

        # --- Blue scoring -------------------------------------------------------
        blue_score = -self.DOWNTIME_PENALTY * sum(r.offline_nodes for r in history)
        true_pos = false_pos = 0
        for r in history:
            if r.blue_action and r.blue_effective and r.blue_action.type in self.CONTAINMENT:
                if r.blue_target_compromised:
                    true_pos += 1
                else:
                    false_pos += 1
        blue_score += self.TRUE_POSITIVE_REWARD * true_pos
        blue_score -= self.FALSE_POSITIVE_PENALTY * false_pos
        if env.red_exfiltrated:
            blue_score -= self.EXFIL_BONUS

        # --- Purple coverage ----------------------------------------------------
        # The true-positive event (if any) each Red action produced, keyed by the
        # step and host it happened on. Events still in flight at game end were
        # never seen, so only visible ones count.
        tp_event = {(e.step_emitted, e.node): e
                    for e in env.bus.visible_events() if e.is_true_positive}
        # A patch only counts while the host is still clean: it doesn't evict anyone.
        responses: Dict[str, List[int]] = {}
        for r in history:
            if not (r.blue_action and r.blue_effective and r.blue_action.type in self.RESPONSES):
                continue
            if r.blue_action.type == "PATCH" and r.blue_target_compromised:
                continue
            responses.setdefault(r.blue_action.params.get("target", ""), []).append(r.step)

        coverage_rows = []
        for r in history:
            ra = r.red_action
            if not (ra and r.red_executed and ra.type in self.MATERIAL):
                continue
            node = ra.params.get("target", "")
            event = tp_event.get((r.step, node))
            seen_at: Optional[int] = event.visible_at if event else None
            response: Optional[int] = None
            if seen_at is not None:
                response = next((s for s in responses.get(node, []) if s >= seen_at), None)
            coverage_rows.append({
                "step": r.step, "action": ra.type, "node": node,
                "technique": r.red_technique,
                "in_telemetry": seen_at is not None, "seen_at": seen_at,
                "blue_acted": response is not None, "response_step": response,
                "detected": response is not None,
            })

        total = len(coverage_rows)
        detected = sum(row["detected"] for row in coverage_rows)
        coverage_pct = (detected / total * 100) if total else 0.0
        delays = [row["response_step"] - row["step"] for row in coverage_rows if row["detected"]]

        by_technique: Dict[str, Dict[str, int]] = {}
        for row in coverage_rows:
            t = by_technique.setdefault(row["technique"], {"executed": 0, "detected": 0})
            t["executed"] += 1
            t["detected"] += int(row["detected"])

        return {
            "winner": env.winner,
            "termination_reason": env.termination_reason,
            "steps": env.step_count,
            "red_score": red_score,
            "blue_score": blue_score,
            "true_positives": true_pos,
            "false_positives": false_pos,
            "exfiltrated": env.red_exfiltrated,
            "coverage_pct": coverage_pct,
            "coverage_rows": coverage_rows,
            "technique_coverage": by_technique,
            "attack_steps": total,
            "attack_steps_detected": detected,
            "mean_time_to_respond": (sum(delays) / len(delays)) if delays else None,
        }
