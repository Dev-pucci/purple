"""Agent interfaces. Every agent takes a partial view and returns an Action.

Keeping this contract tiny is what lets heuristic, LLM, and RL agents all plug
into the same orchestrator and the same environment.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..env.models import Action, Faction


class RedAgent(ABC):
    faction = Faction.RED

    @abstractmethod
    def act(self, red_view: dict) -> Action:
        """Choose Red's next move given what Red currently knows."""
        raise NotImplementedError

    def reset(self) -> None:  # optional hook
        pass


class BlueAgent(ABC):
    faction = Faction.BLUE

    @abstractmethod
    def act(self, blue_view: dict) -> Action:
        """Choose Blue's next move given the telemetry feed."""
        raise NotImplementedError

    def reset(self) -> None:  # optional hook
        pass
