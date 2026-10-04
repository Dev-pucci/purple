"""Gym-style wrapper + an RL agent stub, so RL training plugs into the same env.

This deliberately does NOT depend on gymnasium — it mirrors the reset()/step()
contract with plain Python so the project runs with zero dependencies. With
gymnasium installed, `agents/gym_env.py` wraps it as a real `gymnasium.Env`,
and `train_rl.py` trains PPO on it.

Design choice: we expose a *single-agent* RL view at a time (train Red against a
fixed Blue policy). Full multi-agent self-play (both sides learning) is the
natural next step — see train_notes() at the bottom.

The observation and action table are built from a fixed node set, so RL uses
the default scenario (random networks change the node set every episode).
"""
from __future__ import annotations

import random
from typing import Callable, Dict, List, Optional

from ..env.environment import Environment
from ..env.models import AccessLevel, Action, Faction, Node, RedActionType
from ..scoring.scorer import Scorer
from .base import BlueAgent, RedAgent
from .heuristic import HeuristicBlue

INVALID_ACTION_PENALTY = 0.1  # nudges the learner off moves that do nothing


def build_action_table(network: Dict[str, Node]) -> List[Action]:
    """Every Red move on this network: WAIT, then per node SCAN / EXPLOIT /
    ESCALATE / EXFILTRATE and a LATERAL_MOVE along each edge."""
    table = [Action(Faction.RED, RedActionType.WAIT.value, {})]
    for name in sorted(network):
        for kind in (RedActionType.SCAN, RedActionType.EXPLOIT,
                     RedActionType.ESCALATE, RedActionType.EXFILTRATE):
            table.append(Action(Faction.RED, kind.value, {"target": name}))
        for neigh in network[name].connections:
            table.append(Action(Faction.RED, RedActionType.LATERAL_MOVE.value,
                                {"source": name, "target": neigh}))
    return table


FEATURES_PER_NODE = 10


def encode_red_view(view: dict, node_names: List[str]) -> List[float]:
    """Flat vector in [0, 1]: turn progress, then per node [discovered, reachable,
    held, access/2, isolated, scanned, has known vulns, can escalate, crown
    jewel, exfil progress]."""
    obs: List[float] = [min(1.0, view["step"] / view["max_steps"])]
    for name in node_names:
        info = view["nodes"].get(name)
        if info is None:
            obs += [0.0] * FEATURES_PER_NODE
            continue
        obs += [1.0,
                float(info["reachable"]),
                float(info["compromised_by_me"]),
                info["access"] / float(AccessLevel.ADMIN),
                float(info["isolated"]),
                float(info["scanned"]),
                float(bool(info["known_vulns"])),
                float(info["can_escalate"]),
                float(info["is_crown_jewel"]),
                min(1.0, info["exfil_progress"] / view["exfil_steps"])]
    return obs


def action_mask(view: dict, table: List[Action]) -> List[bool]:
    """Which moves in `table` can do something this turn, judged from Red's own
    view only (so it leaks nothing). WAIT is always allowed."""
    nodes = view["nodes"]
    admin = int(AccessLevel.ADMIN)
    mask = []
    for a in table:
        target = a.params.get("target", "")
        info = nodes.get(target)
        if a.type == RedActionType.WAIT.value:
            ok = True
        elif a.type == RedActionType.SCAN.value:  # incl. own unscanned footholds
            ok = bool(info and info["reachable"]
                      and (not info["compromised_by_me"] or not info["scanned"]))
        elif a.type == RedActionType.EXPLOIT.value:
            ok = bool(info and info["reachable"] and not info["compromised_by_me"]
                      and info["scanned"] and info["known_vulns"])
        elif a.type == RedActionType.ESCALATE.value:
            ok = bool(info and info["can_escalate"])
        elif a.type == RedActionType.EXFILTRATE.value:
            ok = bool(info and info["is_crown_jewel"] and info["compromised_by_me"]
                      and info["reachable"] and info["access"] >= admin)
        else:  # LATERAL_MOVE
            ok = bool(info and a.params.get("source", "") in info["lateral_from"])
        mask.append(ok)
    return mask


def _default_factory(seed: int) -> Environment:
    return Environment(config={"seed": seed})


class PurpleRedEnv:
    """Single-agent RL environment where the *Red* agent is the learner.

    Blue is driven by a fixed policy (default: HeuristicBlue). Each reset()
    starts a new game on a fresh seed, so the learner can't memorise one run.

    Reward per step = change in Red's ground-truth position (footholds, +exfil
    bonus; negative when evicted) + the stealth bonus for footholds Blue hasn't
    seen yet - a small penalty for moves that didn't reach the network.
    """

    def __init__(self, blue_policy: Optional[BlueAgent] = None,
                 env_factory: Callable[[int], Environment] = _default_factory,
                 seed: int = 0):
        self._env_factory = env_factory
        self.blue = blue_policy or HeuristicBlue()
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
        return 1 + FEATURES_PER_NODE * len(self.node_names)

    def _encode_obs(self) -> List[float]:
        return encode_red_view(self.env.red_view(), self.node_names)

    def action_mask(self) -> List[bool]:
        return action_mask(self.env.red_view(), self.action_table)

    # ---- gym-style API
    def reset(self, seed: Optional[int] = None):
        episode_seed = seed if seed is not None else self.seed_rng.randrange(2 ** 31)
        self.env = self._env_factory(episode_seed)
        self.node_names = sorted(self.env.nodes.keys())
        self.blue.reset()
        self.action_table = build_action_table(self.env.nodes)
        return self._encode_obs()

    def step(self, action_index: int):
        assert self.env is not None, "Call reset() first."
        red_action = self.action_table[action_index % len(self.action_table)]

        before = self._scorer.score_state(self.env)
        result = self.env.step(red_action, self.blue.act)  # Blue decides mid-turn
        after = self._scorer.score_state(self.env)

        reward = float(after["red"] - before["red"])
        reward += self._scorer.STEALTH_PER_STEP * result.undetected_footholds
        if red_action.type != RedActionType.WAIT.value and not result.red_executed:
            reward -= INVALID_ACTION_PENALTY
        info = {"red_outcome": result.red_outcome, "blue_outcome": result.blue_outcome,
                "winner": self.env.winner}
        return self._encode_obs(), reward, result.done, info


class PolicyRed(RedAgent):
    """Plays any `(obs, valid-action mask) -> action index` policy (e.g. a
    trained PPO model) as a normal Red agent, so it runs in the Orchestrator."""

    def __init__(self, predict: Callable[[List[float], List[bool]], int],
                 network: Dict[str, Node], label: str = "rl-policy"):
        self.predict = predict
        self.node_names = sorted(network)
        self.action_table = build_action_table(network)
        self.label = label

    def act(self, red_view: dict) -> Action:
        obs = encode_red_view(red_view, self.node_names)
        idx = int(self.predict(obs, action_mask(red_view, self.action_table)))
        a = self.action_table[idx % len(self.action_table)]
        return Action(a.faction, a.type, dict(a.params), f"[{self.label}]")


class RandomRLAgent:
    """Stub learner: samples random action indices. Replace with a real policy
    (e.g. stable-baselines3 PPO, see train_rl.py) that consumes obs."""

    def __init__(self, env: PurpleRedEnv, seed: int = 0):
        self.env = env
        self.rng = random.Random(seed)

    def act(self, obs: List[float]) -> int:
        return self.rng.randrange(self.env.action_space_n)


def train_notes() -> str:
    return (
        "To train a real RL Red agent:\n"
        "  pip install gymnasium stable-baselines3 sb3-contrib\n"
        "  python train_rl.py --timesteps 200000\n"
        "That wraps PurpleRedEnv as a gymnasium.Env (agents/gym_env.py), trains MaskablePPO\n"
        "against the heuristic Blue, saves models/ppo_red.zip and compares it with the\n"
        "heuristic and random Red on held-out seeds. Then:\n"
        "  python run.py --red rl --rl-model models/ppo_red.zip\n"
        "For self-play (both sides learning), alternate: freeze Blue, train Red;\n"
        "then freeze the improved Red, train a Blue env; repeat.\n"
    )
