"""Gym-style wrapper + an RL agent stub, so RL training plugs into the same env.

This deliberately does NOT depend on gymnasium — it mirrors the reset()/step()
contract with plain Python so the project runs with zero dependencies. If you
install gymnasium you can make PurpleRedEnv subclass gymnasium.Env almost
verbatim; the observation/action encoding below is already flat and numeric.

Design choice: we expose a *single-agent* RL view at a time (train Red against a
fixed Blue policy, or vice versa). Full multi-agent self-play (both sides
learning) is the natural next step — see train_notes() at the bottom.
"""
from __future__ import annotations

import random
from typing import Callable, List, Optional

from ..env.environment import Environment
from ..env.models import Action, BlueActionType, Faction, RedActionType
from ..scoring.scorer import Scorer
from .base import BlueAgent, RedAgent
from .heuristic import HeuristicBlue, HeuristicRed


class PurpleRedEnv:
    """Single-agent RL environment where the *Red* agent is the learner.

    Blue is driven by a fixed policy (default: HeuristicBlue). Observation is a
    flat float vector; action is an integer index into an enumerated action list
    built from the current node set.
    """

    def __init__(self, blue_policy: Optional[BlueAgent] = None,
                 env_factory: Callable[[], Environment] = Environment,
                 seed: int = 0):
        self._env_factory = env_factory
        self.blue = blue_policy or HeuristicBlue()
        self.rng = random.Random(seed)
        self.env: Optional[Environment] = None
        self.node_names: List[str] = []
        self.action_table: List[Action] = []
        self._scorer = Scorer()

    # ---- spaces (described as ints/shapes; swap in gym.spaces if you install it)
    def _build_action_table(self) -> None:
        self.action_table = [Action(Faction.RED, RedActionType.WAIT.value, {})]
        for name in self.node_names:
            self.action_table.append(
                Action(Faction.RED, RedActionType.SCAN.value, {"target": name}))
            self.action_table.append(
                Action(Faction.RED, RedActionType.EXPLOIT.value, {"target": name}))
            self.action_table.append(
                Action(Faction.RED, RedActionType.EXFILTRATE.value, {"target": name}))
            for neigh in self.env.nodes[name].connections:
                self.action_table.append(
                    Action(Faction.RED, RedActionType.LATERAL_MOVE.value,
                           {"source": name, "target": neigh}))

    @property
    def action_space_n(self) -> int:
        return len(self.action_table)

    def _encode_obs(self) -> List[float]:
        """Flat vector: per node [discovered, reachable, compromised_by_me, isolated]."""
        view = self.env.red_view()
        obs: List[float] = [float(self.env.step_count) / self.env.max_steps]
        for name in self.node_names:
            info = view["nodes"].get(name)
            if info is None:
                obs += [0.0, 0.0, 0.0, 0.0]
            else:
                obs += [1.0,
                        1.0 if info["reachable"] else 0.0,
                        1.0 if info["compromised_by_me"] else 0.0,
                        1.0 if info["isolated"] else 0.0]
        return obs

    @property
    def obs_dim(self) -> int:
        return 1 + 4 * len(self.node_names)

    # ---- gym-style API
    def reset(self):
        self.env = self._env_factory()
        self.node_names = sorted(self.env.nodes.keys())
        self.blue.reset()
        self._build_action_table()
        return self._encode_obs()

    def step(self, action_index: int):
        assert self.env is not None, "Call reset() first."
        red_action = self.action_table[action_index % len(self.action_table)]

        before = self._scorer.score_state(self.env)
        result = self.env.step(red_action, self.blue.act)  # Blue decides mid-turn
        after = self._scorer.score_state(self.env)

        # Reward = change in Red's advantage this step (+exfil bonus handled in scorer)
        reward = (after["red"] - before["red"])
        done = result.done
        info = {"red_outcome": result.red_outcome, "blue_outcome": result.blue_outcome,
                "winner": self.env.winner}
        return self._encode_obs(), reward, done, info


class RandomRLAgent:
    """Stub learner: samples random valid action indices. Replace with a real
    policy (e.g. stable-baselines3 PPO) that consumes obs and returns an index."""

    def __init__(self, env: PurpleRedEnv, seed: int = 0):
        self.env = env
        self.rng = random.Random(seed)

    def act(self, obs: List[float]) -> int:
        return self.rng.randrange(self.env.action_space_n)


def train_notes() -> str:
    return (
        "To train a real RL Red agent:\n"
        "  pip install gymnasium stable-baselines3\n"
        "  - Make PurpleRedEnv subclass gymnasium.Env; set self.observation_space =\n"
        "    spaces.Box(low=0, high=1, shape=(obs_dim,)) and self.action_space =\n"
        "    spaces.Discrete(action_space_n).\n"
        "  - from stable_baselines3 import PPO; model = PPO('MlpPolicy', env);\n"
        "    model.learn(total_timesteps=200_000).\n"
        "For self-play (both sides learning), alternate: freeze Blue, train Red;\n"
        "then freeze the improved Red, train a PurpleBlueEnv Blue; repeat.\n"
    )
