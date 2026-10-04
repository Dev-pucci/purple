"""Deterministic baseline agents — no dependencies, always runnable.

These encode a simple but sensible strategy for each side. They serve three
purposes: (1) a zero-setup default so `python run.py` works out of the box,
(2) a baseline to measure LLM/RL agents against, and (3) the fallback "brain"
that mock-mode LLM agents use when no API key is configured.
"""
from __future__ import annotations

from typing import List, Optional

from ..env.models import Action, AccessLevel, BlueActionType, Faction, RedActionType
from .base import BlueAgent, RedAgent

ADMIN = int(AccessLevel.ADMIN)


class HeuristicRed(RedAgent):
    """Kill-chain Red: recon -> gain a foothold -> escalate / pivot inward ->
    reach the crown jewel at ADMIN -> exfiltrate."""

    def act(self, red_view: dict) -> Action:
        nodes = red_view["nodes"]
        jewel = next((n for n, i in nodes.items() if i["is_crown_jewel"]), None)

        def red(kind, **params):
            return Action(Faction.RED, kind, params)

        # 1. Endgame on the crown jewel.
        if jewel and nodes[jewel]["compromised_by_me"]:
            j = nodes[jewel]
            if j["reachable"] and j["access"] >= ADMIN:
                return red(RedActionType.EXFILTRATE.value, target=jewel)
            if j["reachable"] and j["can_escalate"]:
                return red(RedActionType.ESCALATE.value, target=jewel)
            if j["reachable"] and not j["scanned"]:
                return red(RedActionType.SCAN.value, target=jewel)

        # 2. Push into the crown jewel if we can see/reach it.
        if jewel and jewel in nodes:
            j = nodes[jewel]
            if j["lateral_from"]:
                return red(RedActionType.LATERAL_MOVE.value,
                           source=j["lateral_from"][0], target=jewel)
            if j["reachable"] and j["scanned"] and j["known_vulns"]:
                return red(RedActionType.EXPLOIT.value, target=jewel)
            if j["reachable"] and not j["scanned"]:
                return red(RedActionType.SCAN.value, target=jewel)
            # Can't cross into it yet: get ADMIN on a foothold adjacent to it.
            for h, info in nodes.items():
                if info["compromised_by_me"] and jewel in info["connections"]:
                    if info["can_escalate"]:
                        return red(RedActionType.ESCALATE.value, target=h)
                    if not info["scanned"]:
                        return red(RedActionType.SCAN.value, target=h)

        # 3. General kill-chain on the reachable frontier.
        exploitable = [(i["is_crown_jewel"], -self._value(i), n)
                       for n, i in nodes.items()
                       if i["reachable"] and not i["compromised_by_me"]
                       and i["scanned"] and i["known_vulns"]]
        if exploitable:
            return red(RedActionType.EXPLOIT.value, target=min(exploitable)[2])

        # Scan anything reachable we haven't fingerprinted — including our own
        # fresh footholds, to reveal their neighbours.
        unscanned = [n for n, i in nodes.items() if i["reachable"] and not i["scanned"]]
        if unscanned:
            return red(RedActionType.SCAN.value, target=sorted(unscanned)[0])

        # Pivot into any node we hold credentials for, crown-jewel segment first.
        pivots = sorted((n for n, i in nodes.items() if i["lateral_from"]),
                        key=lambda n: (nodes[n]["segment"] not in red_view["admin_segments"],
                                       -self._value(nodes[n]), n))
        if pivots:
            t = pivots[0]
            return red(RedActionType.LATERAL_MOVE.value,
                       source=nodes[t]["lateral_from"][0], target=t)

        # Escalate a foothold that sits next to somewhere we still need to reach.
        for n, i in nodes.items():
            if i["compromised_by_me"] and i["can_escalate"] and self._opens_path(n, nodes):
                return red(RedActionType.ESCALATE.value, target=n)

        return red(RedActionType.WAIT.value)

    @staticmethod
    def _value(info: dict) -> int:
        return 5 if info["is_crown_jewel"] else 1

    @staticmethod
    def _opens_path(name: str, nodes: dict) -> bool:
        """True if a neighbour is a node we don't yet hold (ADMIN may let us cross)."""
        return any(not nodes.get(c, {}).get("compromised_by_me", True)
                   for c in nodes[name]["connections"])


class PlannerRed(HeuristicRed):
    """A stealth-aware attacker: plays the same kill chain as HeuristicRed but
    goes *quiet* (mode="stealth") on the highest-scrutiny moves — anything in the
    secure zone or on the crown jewel — trading success odds for far lower
    detection where the defender is watching hardest. Uses only what Red can see
    (segment, crown-jewel flag), no privileged knowledge of sensors."""

    QUIET_ACTIONS = {RedActionType.EXPLOIT.value, RedActionType.ESCALATE.value,
                     RedActionType.LATERAL_MOVE.value, RedActionType.EXFILTRATE.value}

    def act(self, red_view: dict) -> Action:
        action = super().act(red_view)
        if action.type in self.QUIET_ACTIONS:
            info = red_view["nodes"].get(action.params.get("target", ""), {})
            if info.get("is_crown_jewel") or info.get("segment") == "secure":
                action.params["mode"] = "stealth"
        return action


class HeuristicBlue(BlueAgent):
    """SOC-analyst Blue: build suspicion from telemetry, then contain/patch/investigate,
    rationing a finite pool of analyst action-points.

    Blue only ever sees the telemetry feed — never ground truth. It scores each
    node by recent attack-shaped events (ignoring benign noise and alerts that
    predate its own re-image of a host) and escalates: contain a hot node >
    patch a host under exploit pressure > investigate. It skips any action it
    can't afford and falls back to a cheaper one.
    """

    INVESTIGATE_AT = 1
    CONTAIN_AT = 2
    SUSPICION_WINDOW = 8

    WEIGHTS = {"SCAN_DETECTED": 1, "EXPLOIT_ATTEMPT": 2, "PRIVESC_DETECTED": 3,
               "LATERAL_DETECTED": 3, "EXFIL_DETECTED": 3}
    COST = {"INVESTIGATE": 1, "PATCH": 2, "ISOLATE": 2, "RESTORE": 3}

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._investigated: set = set()
        self._patched: set = set()
        self._cleared_at: dict = {}
        self._budget: Optional[int] = None

    def _afford(self, action_type: str) -> bool:
        return self._budget is None or self._budget <= 0 or \
            self.COST.get(action_type, 0) <= self._budget

    def _live_alerts(self, telemetry: list, now: int) -> list:
        alerts = []
        for e in telemetry:
            step = int(e["step"])
            if e["kind"] not in self.WEIGHTS or now - step >= self.SUSPICION_WINDOW:
                continue
            if step <= self._cleared_at.get(e["node"], -1):
                continue
            alerts.append(e)
        return alerts

    def act(self, blue_view: dict) -> Action:
        now = blue_view["step"]
        nodes = blue_view["nodes"]
        budget = blue_view.get("analyst_budget", 0)
        self._budget = blue_view.get("analyst_remaining") if budget else None
        alerts = self._live_alerts(blue_view["telemetry"], now)

        def blue(kind, target):
            return Action(Faction.BLUE, kind, {"target": target})

        scores: dict = {}
        for e in alerts:
            scores[e["node"]] = scores.get(e["node"], 0) + self.WEIGHTS[e["kind"]]
        ranked = sorted(scores, key=lambda n: (-scores[n], n))

        # 1. Strong signal -> contain. Isolate first (cheap); re-image to evict.
        for name in ranked:
            if scores[name] < self.CONTAIN_AT:
                break
            info = nodes[name]
            if info["restoring"]:
                continue
            if (info["is_crown_jewel"] or info["isolated"]) and self._afford("RESTORE"):
                self._cleared_at[name] = now
                return blue(BlueActionType.RESTORE.value, name)
            if not info["isolated"] and self._afford("ISOLATE"):
                return blue(BlueActionType.ISOLATE.value, name)

        # 2. Exploit attempts on a host -> patch it (cheap, closes the vector).
        for e in alerts:
            if e["kind"] == "EXPLOIT_ATTEMPT" and e["node"] not in self._patched \
                    and self._afford("PATCH"):
                self._patched.add(e["node"])
                return blue(BlueActionType.PATCH.value, e["node"])

        # 3. Weaker signal -> investigate once (also sharpens blind-spot sensors).
        for name in ranked:
            if scores[name] >= self.INVESTIGATE_AT and name not in self._investigated \
                    and self._afford("INVESTIGATE"):
                self._investigated.add(name)
                return blue(BlueActionType.INVESTIGATE.value, name)

        return Action(Faction.BLUE, BlueActionType.MONITOR.value, {})
