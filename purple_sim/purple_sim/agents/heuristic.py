"""Deterministic baseline agents — no dependencies, always runnable.

These encode a simple but sensible strategy for each side. They serve three
purposes: (1) a zero-setup default so `python run.py` works out of the box,
(2) a baseline to measure LLM/RL agents against, and (3) the fallback "brain"
that mock-mode LLM agents use when no API key is configured.
"""
from __future__ import annotations

from typing import Optional

from ..env.models import Action, BlueActionType, Faction, RedActionType
from .base import BlueAgent, RedAgent


class HeuristicRed(RedAgent):
    """Kill-chain Red: recon -> exploit/pivot hop by hop to the crown jewel -> exfiltrate."""

    def act(self, red_view: dict) -> Action:
        nodes = red_view["nodes"]
        footholds = set(red_view["footholds"])

        # 1. If we're sitting on a reachable crown jewel, steal the data.
        for name, info in nodes.items():
            if info["is_crown_jewel"] and info["compromised_by_me"] and info["reachable"]:
                return Action(Faction.RED, RedActionType.EXFILTRATE.value,
                              {"target": name}, "On the crown jewel — exfiltrate.")

        # 2. Work the reachable frontier, crown jewel first: scan, exploit, or
        #    fall back to a credentialed pivot when the host has been patched.
        frontier = sorted(
            (n for n, i in nodes.items() if i["reachable"] and not i["compromised_by_me"]),
            key=lambda n: (not nodes[n]["is_crown_jewel"], n))
        for name in frontier:
            info = nodes[name]
            if not info["scanned"]:
                return Action(Faction.RED, RedActionType.SCAN.value,
                              {"target": name}, f"Scan {name} to find vulns.")
            if info["known_vulns"]:
                return Action(Faction.RED, RedActionType.EXPLOIT.value,
                              {"target": name}, f"Exploit {name} (known vuln).")
            src = self._adjacent_foothold(name, nodes, footholds)
            if src:
                return Action(Faction.RED, RedActionType.LATERAL_MOVE.value,
                              {"source": src, "target": name},
                              f"{name} is patched — pivot in from {src} with credentials.")

        # 3. Map the neighbourhood of a foothold we took without scanning.
        for name in sorted(footholds):
            info = nodes.get(name)
            if info and info["reachable"] and not info["scanned"]:
                return Action(Faction.RED, RedActionType.SCAN.value, {"target": name},
                              f"Scan own foothold {name} to reveal neighbours.")

        return Action(Faction.RED, RedActionType.WAIT.value, {}, "No route forward — lie low.")

    @staticmethod
    def _adjacent_foothold(target: str, nodes: dict, footholds: set) -> Optional[str]:
        for src in sorted(footholds):
            info = nodes.get(src)
            if info and info["reachable"] and target in info["connections"]:
                return src
        return None


class HeuristicBlue(BlueAgent):
    """SOC-analyst Blue: build suspicion from telemetry, then contain/patch/investigate.

    Blue only ever sees the telemetry feed — it never reads ground truth. It
    scores each node by recent *attack-shaped* events, ignores benign noise and
    alerts that predate its own re-image of a host, and escalates. Priority:
    contain a hot node > patch a host seeing exploit attempts > investigate.
    """

    # suspicion thresholds (tuned so heuristic vs heuristic is roughly even)
    INVESTIGATE_AT = 1
    CONTAIN_AT = 2
    SUSPICION_WINDOW = 8   # alerts older than this many steps age out

    WEIGHTS = {"SCAN_DETECTED": 1, "EXPLOIT_ATTEMPT": 2,
               "LATERAL_DETECTED": 3, "EXFIL_DETECTED": 3}

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._investigated: set = set()
        self._patched: set = set()
        self._cleared_at: dict = {}   # node -> step Blue re-imaged it

    def _live_alerts(self, telemetry: list, now: int) -> list:
        """Attack-shaped events that are recent and still relevant."""
        alerts = []
        for e in telemetry:
            step = int(e["step"])
            if e["kind"] not in self.WEIGHTS or now - step >= self.SUSPICION_WINDOW:
                continue
            if step <= self._cleared_at.get(e["node"], -1):
                continue  # predates our re-image of this host
            alerts.append(e)
        return alerts

    def act(self, blue_view: dict) -> Action:
        now = blue_view["step"]
        nodes = blue_view["nodes"]
        alerts = self._live_alerts(blue_view["telemetry"], now)

        scores: dict = {}
        for e in alerts:
            scores[e["node"]] = scores.get(e["node"], 0) + self.WEIGHTS[e["kind"]]
        ranked = sorted(scores, key=lambda n: (-scores[n], n))

        # 1. Strong signal -> contain. Isolate first; re-image to evict.
        for name in ranked:
            if scores[name] < self.CONTAIN_AT:
                break
            info = nodes[name]
            if info["restoring"]:
                continue
            if info["is_crown_jewel"] or info["isolated"]:
                self._cleared_at[name] = now
                return Action(Faction.BLUE, BlueActionType.RESTORE.value, {"target": name},
                              f"Strong signal on {name} — re-image to evict.")
            return Action(Faction.BLUE, BlueActionType.ISOLATE.value, {"target": name},
                          f"Strong signal on {name} — isolate.")

        # 2. Exploit attempts against a host -> patch it (cheap, no downtime).
        for e in alerts:
            if e["kind"] == "EXPLOIT_ATTEMPT" and e["node"] not in self._patched:
                self._patched.add(e["node"])
                return Action(Faction.BLUE, BlueActionType.PATCH.value, {"target": e["node"]},
                              f"Exploit attempts on {e['node']} — patch it.")

        # 3. Weaker signal -> investigate once to improve detection.
        for name in ranked:
            if scores[name] >= self.INVESTIGATE_AT and name not in self._investigated:
                self._investigated.add(name)
                return Action(Faction.BLUE, BlueActionType.INVESTIGATE.value,
                              {"target": name},
                              f"Suspicious activity on {name} — raise monitoring.")

        # Nothing actionable -> keep watching.
        return Action(Faction.BLUE, BlueActionType.MONITOR.value, {},
                      "No clear threat — continue monitoring.")
