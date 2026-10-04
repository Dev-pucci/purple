"""A stronger, budget-aware SOC-analyst Blue.

Where HeuristicBlue reacts to the single hottest host, SOCBlue tries to behave
like a thoughtful analyst working under a time budget:

- **Recency-weighted, severity-weighted suspicion.** A fresh exfil alert counts
  far more than a stale scan; old alerts fade out of the picture.
- **Correlation across hosts.** Signal on a host's neighbours raises its score —
  lateral movement lights up a path, not a point.
- **Blind-spot awareness.** A host whose ENDPOINT sensor is weak gets an early,
  cheap INVESTIGATE (which lifts detection even where a sensor is absent) rather
  than being left dark until it's too late.
- **Budget discipline.** It rations analyst points: cheap triage early, and it
  reserves enough to afford a containment when a real intrusion matures, instead
  of blowing the budget chasing noise.

Like every Blue it sees only telemetry — never ground truth.
"""
from __future__ import annotations

from typing import Optional

from ..env.models import Action, BlueActionType, Faction
from .base import BlueAgent

SEVERITY = {"EXFIL_DETECTED": 5, "PRIVESC_DETECTED": 4, "LATERAL_DETECTED": 4,
            "EXPLOIT_ATTEMPT": 2, "SCAN_DETECTED": 1}


class SOCBlue(BlueAgent):
    WINDOW = 10            # alerts older than this fade to nothing
    CONTAIN_AT = 4.0       # weighted suspicion needed to cut a host off
    INVESTIGATE_AT = 1.0
    NEIGHBOUR_BOOST = 0.4  # how much a noisy neighbour adds to a host's score
    WEAK_SENSOR = 0.3      # ENDPOINT coverage at/below this is a blind spot
    COST = {"INVESTIGATE": 1, "PATCH": 2, "ISOLATE": 2, "RESTORE": 3,
            "DECOY": 1, "ROTATE_CREDS": 2}

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._patched: set = set()
        self._investigated: set = set()
        self._cleared_at: dict = {}
        self._budget: Optional[int] = None
        self._max_budget: int = 0

    # -- budget -----------------------------------------------------------------
    def _afford(self, action_type: str, reserve: int = 0) -> bool:
        if self._budget is None:
            return True
        return self.COST.get(action_type, 0) <= self._budget - reserve

    def _reserve(self, now: int, max_steps: int) -> int:
        """Keep a containment in the bank until late game; relax as time runs out."""
        if self._budget is None or max_steps <= 0:
            return 0
        return self.COST["RESTORE"] if now < 0.75 * max_steps else 0

    # -- perception -------------------------------------------------------------
    def _scores(self, telemetry: list, nodes: dict, now: int) -> dict:
        raw: dict = {}
        for e in telemetry:
            sev = SEVERITY.get(e["kind"])
            if sev is None:
                continue
            step = int(e["step"])
            age = now - step
            if age >= self.WINDOW or step <= self._cleared_at.get(e["node"], -1):
                continue
            weight = sev * (1.0 - age / self.WINDOW)
            raw[e["node"]] = raw.get(e["node"], 0.0) + weight
        # Correlate: a host inherits a share of its noisy neighbours' suspicion.
        scores = dict(raw)
        for name, info in nodes.items():
            for neigh in info.get("connections", []):
                if neigh in raw:
                    scores[name] = scores.get(name, 0.0) + self.NEIGHBOUR_BOOST * raw[neigh]
        return scores

    # -- policy -----------------------------------------------------------------
    def act(self, blue_view: dict) -> Action:
        now = blue_view["step"]
        max_steps = blue_view.get("max_steps", 0)
        nodes = blue_view["nodes"]
        budget_on = blue_view.get("analyst_budget", 0)
        self._budget = blue_view.get("analyst_remaining") if budget_on else None
        scores = self._scores(blue_view["telemetry"], nodes, now)
        reserve = self._reserve(now, max_steps)

        def blue(kind, target):
            return Action(Faction.BLUE, kind, {"target": target})

        ranked = sorted(scores, key=lambda n: (-scores[n], n))

        # 1. Contain a strongly-suspicious host. Protect the crown jewel hardest.
        for name in ranked:
            if scores[name] < self.CONTAIN_AT:
                break
            info = nodes[name]
            if info["restoring"] or info["patching"]:
                continue
            jewel_or_secure = info["is_crown_jewel"] or info["segment"] == "secure"
            if (jewel_or_secure or info["isolated"]) and self._afford("RESTORE"):
                self._cleared_at[name] = now
                return blue(BlueActionType.RESTORE.value, name)
            if not info["isolated"] and self._afford("ISOLATE", reserve):
                return blue(BlueActionType.ISOLATE.value, name)

        # 2. A host under exploit pressure -> patch it shut (cheap, no eviction).
        for name in ranked:
            info = nodes[name]
            if (name not in self._patched and scores[name] >= self.INVESTIGATE_AT
                    and not info["patching"] and self._afford("PATCH", reserve)):
                if any(e["node"] == name and e["kind"] == "EXPLOIT_ATTEMPT"
                       for e in blue_view["telemetry"]):
                    self._patched.add(name)
                    return blue(BlueActionType.PATCH.value, name)

        # 3. Triage: investigate a suspicious host, prioritising blind spots where
        #    INVESTIGATE buys the most (it adds detection even with no sensor).
        triage = [n for n in ranked if scores[n] >= self.INVESTIGATE_AT
                  and n not in self._investigated]
        triage.sort(key=lambda n: (nodes[n]["sensors"].get("ENDPOINT", 0.0) > self.WEAK_SENSOR,
                                    -scores[n]))
        for name in triage:
            if self._afford("INVESTIGATE", reserve):
                self._investigated.add(name)
                return blue(BlueActionType.INVESTIGATE.value, name)

        return Action(Faction.BLUE, BlueActionType.MONITOR.value, {})


class AdaptiveBlue(SOCBlue):
    """SOCBlue plus proactive tools: a canary on the crown jewel, and credential
    rotation on an identity host under attack (revoking the attacker's domain
    reach). Everything else falls through to SOCBlue's triage/containment.
    """

    def reset(self) -> None:
        super().reset()
        self._decoyed: set = set()

    def act(self, blue_view: dict):
        now = blue_view["step"]
        nodes = blue_view["nodes"]
        budget_on = blue_view.get("analyst_budget", 0)
        self._budget = blue_view.get("analyst_remaining") if budget_on else None

        def blue(kind, target):
            return Action(Faction.BLUE, kind, {"target": target})

        # 1. Plant a canary on the crown jewel once — a cheap, reliable tripwire
        #    on the thing that actually matters.
        jewel = next((n for n, i in nodes.items() if i["is_crown_jewel"]), None)
        if (jewel and jewel not in self._decoyed and not nodes[jewel].get("decoy")
                and self._afford("DECOY")):
            self._decoyed.add(jewel)
            return blue(BlueActionType.DECOY.value, jewel)

        # 2. Rotate credentials on an identity host under strong, recent attack,
        #    to revoke any domain-admin reach the attacker may have gained.
        scores = self._scores(blue_view["telemetry"], nodes, now)
        for name, score in sorted(scores.items(), key=lambda kv: -kv[1]):
            info = nodes.get(name, {})
            if (info.get("is_identity") and score >= self.CONTAIN_AT
                    and not info.get("restoring") and self._afford("ROTATE_CREDS")):
                return blue(BlueActionType.ROTATE_CREDS.value, name)

        return super().act(blue_view)
