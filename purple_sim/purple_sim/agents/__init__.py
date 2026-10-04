"""Agents subpackage: heuristic, LLM (mock/real Claude), and RL interfaces."""
from .base import BlueAgent, RedAgent
from .heuristic import HeuristicBlue, HeuristicRed
from .llm_agents import LLMBlue, LLMRed
from .rl_interface import PurpleRedEnv, RandomRLAgent, train_notes

__all__ = [
    "RedAgent", "BlueAgent",
    "HeuristicRed", "HeuristicBlue",
    "LLMRed", "LLMBlue",
    "PurpleRedEnv", "RandomRLAgent", "train_notes",
]


def make_red(kind: str, mock: bool = True):
    kind = kind.lower()
    if kind == "heuristic":
        return HeuristicRed()
    if kind == "llm":
        return LLMRed(mock=mock)
    raise ValueError(f"Unknown red agent kind: {kind!r} (use heuristic|llm)")


def make_blue(kind: str, mock: bool = True):
    kind = kind.lower()
    if kind == "heuristic":
        return HeuristicBlue()
    if kind == "llm":
        return LLMBlue(mock=mock)
    raise ValueError(f"Unknown blue agent kind: {kind!r} (use heuristic|llm)")
