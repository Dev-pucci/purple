"""Agents subpackage: heuristic, LLM (mock/real Claude), and RL interfaces."""
from .base import BlueAgent, RedAgent
from .heuristic import HeuristicBlue, HeuristicRed, PlannerRed
from .llm_agents import LLMBlue, LLMRed
from .rl_interface import PolicyRed, PurpleRedEnv, RandomRLAgent, train_notes
from .soc import AdaptiveBlue, SOCBlue

__all__ = [
    "RedAgent", "BlueAgent",
    "HeuristicRed", "PlannerRed", "HeuristicBlue", "SOCBlue", "AdaptiveBlue",
    "LLMRed", "LLMBlue",
    "PurpleRedEnv", "PolicyRed", "RandomRLAgent", "train_notes",
]


def make_red(kind: str, mock: bool = True):
    kind = kind.lower()
    if kind == "heuristic":
        return HeuristicRed()
    if kind == "planner":
        return PlannerRed()
    if kind == "llm":
        return LLMRed(mock=mock)
    raise ValueError(f"Unknown red agent kind: {kind!r} (use heuristic|planner|llm)")


def make_blue(kind: str, mock: bool = True):
    kind = kind.lower()
    if kind == "heuristic":
        return HeuristicBlue()
    if kind == "soc":
        return SOCBlue()
    if kind == "adaptive":
        return AdaptiveBlue()
    if kind == "llm":
        return LLMBlue(mock=mock)
    raise ValueError(f"Unknown blue agent kind: {kind!r} (use heuristic|soc|adaptive|llm)")
