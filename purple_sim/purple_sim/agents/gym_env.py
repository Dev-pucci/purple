"""gymnasium adapter for PurpleRedEnv + loading a trained policy as a Red agent.

Optional: needs `pip install gymnasium stable-baselines3 sb3-contrib`
(sb3-contrib provides MaskablePPO, which uses the valid-move mask). Nothing else in the
package imports this module, so the core project stays dependency-free.
"""
from __future__ import annotations

from typing import Optional

import gymnasium as gym
import numpy as np
from gymnasium import spaces

from ..env.scenario import default_network
from .base import BlueAgent, RedAgent
from .blue_rl import PolicyBlue, PurpleBlueEnv
from .rl_interface import PolicyRed, PurpleRedEnv


class GymRedEnv(gym.Env):
    """PurpleRedEnv as a gymnasium.Env (Red learns, Blue is a fixed policy)."""

    metadata = {"render_modes": []}

    def __init__(self, blue_policy: Optional[BlueAgent] = None, seed: int = 0,
                 shaping: bool = False):
        super().__init__()
        self.inner = PurpleRedEnv(blue_policy=blue_policy, seed=seed, shaping=shaping)
        self.inner.reset()
        self.observation_space = spaces.Box(0.0, 1.0, (self.inner.obs_dim,), dtype=np.float32)
        self.action_space = spaces.Discrete(self.inner.action_space_n)

    def reset(self, *, seed: Optional[int] = None, options: Optional[dict] = None):
        super().reset(seed=seed)
        if seed is not None:  # reseed the episode-seed stream; later resets draw from it
            self.inner.seed_rng.seed(seed)
        obs = self.inner.reset()
        return np.asarray(obs, dtype=np.float32), {}

    def step(self, action):
        obs, reward, done, info = self.inner.step(int(action))
        return np.asarray(obs, dtype=np.float32), float(reward), done, False, info

    def action_masks(self) -> np.ndarray:
        """Valid moves this turn (the hook sb3-contrib's MaskablePPO looks for)."""
        return np.asarray(self.inner.action_mask(), dtype=bool)


class GymBlueEnv(gym.Env):
    """PurpleBlueEnv as a gymnasium.Env (Blue learns, Red is a fixed policy)."""

    metadata = {"render_modes": []}

    def __init__(self, red_policy: Optional[RedAgent] = None, seed: int = 0):
        super().__init__()
        self.inner = PurpleBlueEnv(red_policy=red_policy, seed=seed)
        self.inner.reset()
        self.observation_space = spaces.Box(0.0, 1.0, (self.inner.obs_dim,), dtype=np.float32)
        self.action_space = spaces.Discrete(self.inner.action_space_n)

    def reset(self, *, seed: Optional[int] = None, options: Optional[dict] = None):
        super().reset(seed=seed)
        if seed is not None:
            self.inner.seed_rng.seed(seed)
        obs = self.inner.reset()
        return np.asarray(obs, dtype=np.float32), {}

    def step(self, action):
        obs, reward, done, info = self.inner.step(int(action))
        return np.asarray(obs, dtype=np.float32), float(reward), done, False, info

    def action_masks(self) -> np.ndarray:
        return np.asarray(self.inner.action_mask(), dtype=bool)


def _loader(cls, label):
    from sb3_contrib import MaskablePPO

    def load(path, **kw):
        model = MaskablePPO.load(path, device="cpu")
        agent = cls(lambda obs, mask: 0, default_network(), label=label, **kw)
        expected = len(agent.action_table)
        actual = int(model.action_space.n)
        if actual != expected:
            raise ValueError(
                f"{path} has {actual} actions but the current {label} action table has "
                f"{expected} (the action set changed since it was trained). Retrain with "
                f"train_rl.py and point --rl-model / --rl-blue-model at the new file.")

        def predict(obs, mask):
            action, _ = model.predict(np.asarray(obs, dtype=np.float32),
                                      action_masks=np.asarray(mask, dtype=bool),
                                      deterministic=True)
            return int(action)

        agent.predict = predict
        return agent
    return load


def load_policy_red(path: str) -> PolicyRed:
    """Load a MaskablePPO model saved by train_rl.py --side red as a Red agent."""
    return _loader(PolicyRed, "ppo")(path)


def load_policy_blue(path: str, budget_on: bool = True) -> PolicyBlue:
    """Load a MaskablePPO model saved by train_rl.py --side blue as a Blue agent."""
    return _loader(PolicyBlue, "ppo")(path, budget_on=budget_on)
