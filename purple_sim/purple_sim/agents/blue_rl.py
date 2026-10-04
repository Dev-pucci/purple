"""Blue-side RL: a learnable defender on the same environment.

Mirrors `rl_interface.py` but with the roles swapped — Blue is the learner and
Red is a fixed policy (default: HeuristicRed). Blue sees only `blue_view()`
(telemetry + observable availability), never ground truth, so the observation
is built purely from what a real defender could know.

Reward **is** the honest Blue score, paid out per step: +TRUE_POSITIVE_REWARD
for containing a genuinely compromised host, -FALSE_POSITIVE_PENALTY for
containing a healthy one, -DOWNTIME_PENALTY for every node-step offline, and
-EXFIL_BONUS if Red steals the data. (An earlier version rewarded only "lower
Red's score minus a small waste penalty"; the agent reward-hacked it into
scorched-earth — isolate/re-image everything, win every game at 0% coverage and
a terrible availability cost. Training against the real objective fixes that.)

As with Red, training uses MaskablePPO; the mask marks only actions that are
affordable and not obviously no-ops from what Blue can see.
"""
from __future__ import annotations

import random
from typing import Callable, Dict, List, Optional

from ..env.environment import Environment
from ..env.models import Action, BlueActionType, Faction, Node
from ..scoring.scorer import Scorer
from .base import BlueAgent, RedAgent
from .heuristic import HeuristicRed

ANALYST_COST = {"INVESTIGATE": 1, "PATCH": 2, "ISOLATE": 2, "RESTORE": 3}
ALERT_WINDOW = 10          # steps of telemetry folded into the observation
CONTAINMENT = ("ISOLATE", "RESTORE")
SEVERITY = {"EXFIL_DETECTED": 5, "PRIVESC_DETECTED": 4, "LATERAL_DETECTED": 4,
            "EXPLOIT_ATTEMPT": 2, "SCAN_DETECTED": 1}
_ACTIONS = (BlueActionType.INVESTIGATE, BlueActionType.PATCH,
            BlueActionType.ISOLATE, BlueActionType.RESTORE)


def build_blue_action_table(network: Dict[str, Node]) -> List[Action]:
    """WAIT (MONITOR), then INVESTIGATE / PATCH / ISOLATE / RESTORE per node."""
    table = [Action(Faction.BLUE, BlueActionType.MONITOR.value, {})]
    for name in sorted(network):
        for kind in _ACTIONS:
            table.append(Action(Faction.BLUE, kind.value, {"target": name}))
    return table


FEATURES_PER_NODE = 8


def _alerts(view: dict) -> Dict[str, float]:
    now = view["step"]
    score: Dict[str, float] = {}
    for e in view["telemetry"]:
        sev = SEVERITY.get(e["kind"])
        if sev is None:
            continue
        age = now - int(e["step"])
        if 0 <= age < ALERT_WINDOW:
            score[e["node"]] = score.get(e["node"], 0.0) + sev * (1.0 - age / ALERT_WINDOW)
    return score


def encode_blue_view(view: dict, node_names: List[str]) -> List[float]:
    """Turn progress + analyst budget left, then per node [crown jewel, secure,
    NETWORK cov, ENDPOINT cov, isolated, offline, monitoring, recent suspicion]."""
    budget = view.get("analyst_budget", 0)
    remaining = view.get("analyst_remaining", 0)
    obs: List[float] = [min(1.0, view["step"] / view["max_steps"]),
                        remaining / budget if budget else 1.0]
    alerts = _alerts(view)
    for name in node_names:
        info = view["nodes"].get(name)
        if info is None:
            obs += [0.0] * FEATURES_PER_NODE
            continue
        obs += [float(info["is_crown_jewel"]),
                float(info["segment"] == "secure"),
                float(info["sensors"].get("NETWORK", 0.0)),
                float(info["sensors"].get("ENDPOINT", 0.0)),
                float(info["isolated"]),
                float(info["restoring"] or info["patching"]),
                float(info["monitoring"]),
                min(1.0, alerts.get(name, 0.0) / 6.0)]
    return obs


def blue_action_mask(view: dict, table: List[Action], budget_on: bool) -> List[bool]:
    """Affordable, non-obviously-wasteful moves, from Blue's view only."""
    remaining = view.get("analyst_remaining", 0)
    nodes = view["nodes"]
    mask = []
    for a in table:
        if a.type == BlueActionType.MONITOR.value:
            mask.append(True)
            continue
        info = nodes.get(a.params.get("target", ""))
        cost = ANALYST_COST.get(a.type, 0)
        ok = info is not None and (not budget_on or cost <= remaining)
        if ok:
            if a.type == BlueActionType.ISOLATE.value:
                ok = not info["isolated"]
            elif a.type == BlueActionType.RESTORE.value:
                ok = not info["restoring"]
            elif a.type == BlueActionType.INVESTIGATE.value:
                ok = info["monitoring"] < 1.0 and not info["isolated"]
            # PATCH: Blue can't see whether vulns remain, so always allow if afforded.
        mask.append(bool(ok))
    return mask


def _default_factory(seed: int) -> Environment:
    return Environment(config={"seed": seed})


class PurpleBlueEnv:
    """Single-agent RL environment where the *Blue* agent is the learner."""

    def __init__(self, red_policy: Optional[RedAgent] = None,
                 env_factory: Callable[[int], Environment] = _default_factory,
                 seed: int = 0):
        self._env_factory = env_factory
        self.red = red_policy or HeuristicRed()
        self.seed_rng = random.Random(seed)
        self.env: Optional[Environment] = None
        self.node_names: List[str] = []
        self.action_table: List[Action] = []
        self._scorer = Scorer()

    @property
    def action_space_n(self) -> int:
        return len(self.action_table)

    @property
    def obs_dim(self) -> int:
        return 2 + FEATURES_PER_NODE * len(self.node_names)

    def _budget_on(self) -> bool:
        return self.env.config["analyst_budget"] > 0

    def _encode_obs(self) -> List[float]:
        return encode_blue_view(self.env.blue_view(), self.node_names)

    def action_mask(self) -> List[bool]:
        return blue_action_mask(self.env.blue_view(), self.action_table, self._budget_on())

    def reset(self, seed: Optional[int] = None):
        episode_seed = seed if seed is not None else self.seed_rng.randrange(2 ** 31)
        self.env = self._env_factory(episode_seed)
        self.node_names = sorted(self.env.nodes.keys())
        self.red.reset()
        self.action_table = build_blue_action_table(self.env.nodes)
        return self._encode_obs()

    def step(self, action_index: int):
        assert self.env is not None, "Call reset() first."
        blue_action = self.action_table[action_index % len(self.action_table)]
        red_action = self.red.act(self.env.red_view())
        result = self.env.step(red_action, blue_action)

        # Reward = the honest Blue score, paid incrementally (summing it over a
        # game reproduces Scorer.final_report's blue_score).
        sc = self._scorer
        reward = -sc.DOWNTIME_PENALTY * result.offline_nodes
        if result.blue_effective and blue_action.type in CONTAINMENT:
            reward += (sc.TRUE_POSITIVE_REWARD if result.blue_target_compromised
                       else -sc.FALSE_POSITIVE_PENALTY)
        if self.env.red_exfiltrated:
            reward -= sc.EXFIL_BONUS
        info = {"red_outcome": result.red_outcome, "blue_outcome": result.blue_outcome,
                "winner": self.env.winner}
        return self._encode_obs(), reward, result.done, info


class PolicyBlue(BlueAgent):
    """Plays a trained `(obs, mask) -> action index` policy as a Blue agent."""

    def __init__(self, predict: Callable[[List[float], List[bool]], int],
                 network: Dict[str, Node], budget_on: bool = True, label: str = "rl-blue"):
        self.predict = predict
        self.node_names = sorted(network)
        self.action_table = build_blue_action_table(network)
        self.budget_on = budget_on
        self.label = label

    def reset(self) -> None:
        pass

    def act(self, blue_view: dict) -> Action:
        obs = encode_blue_view(blue_view, self.node_names)
        mask = blue_action_mask(blue_view, self.action_table, self.budget_on)
        idx = int(self.predict(obs, mask))
        a = self.action_table[idx % len(self.action_table)]
        return Action(a.faction, a.type, dict(a.params), f"[{self.label}]")
