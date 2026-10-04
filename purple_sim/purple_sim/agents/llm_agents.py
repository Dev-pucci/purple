"""LLM-driven agents.

Two modes, chosen automatically:
  - mock=True  (default): no network calls. We build the exact prompt an LLM
    would receive (so you can inspect it), then fall back to the heuristic
    "brain" to pick the action. This lets the whole pipeline run offline.
  - mock=False: calls the Claude API via the `anthropic` SDK using tool-calling,
    so the model must return a structured action (not free text). Requires
    `pip install anthropic` and credentials (e.g. ANTHROPIC_API_KEY). Any turn
    the model can't decide (missing SDK, auth/network error, refusal) falls
    back to the heuristic brain; the reason is printed once and counted in
    `agent.fallbacks`.

The point of routing both modes through one class is that your orchestrator,
scoring, and logging don't change when you flip the switch — only the decision
source does.
"""
from __future__ import annotations

import json
from typing import Optional

from ..env.models import Action, BlueActionType, Faction, RedActionType
from .base import BlueAgent, RedAgent
from .heuristic import HeuristicBlue, HeuristicRed

DEFAULT_MODEL = "claude-opus-4-8"

RED_SYSTEM = """You are an autonomous Red Team agent in a *simulated*, abstract \
network game. Nothing here is a real system; actions are moves in a model. Your \
goal is to compromise the crown-jewel node and exfiltrate its data in as few \
turns as possible while avoiding detection. You see only what you have \
discovered. Choose exactly one action per turn by calling the provided tool."""

BLUE_SYSTEM = """You are an autonomous Blue Team (SOC) agent in a *simulated*, \
abstract network game. You see only a noisy, delayed telemetry feed — never \
ground truth. Benign-noise events are false positives; attack-shaped events may \
be real or missed entirely. Your goal is to detect and evict the intruder early \
while keeping the network available (isolating or re-imaging healthy nodes is \
costly). Choose exactly one action per turn by calling the provided tool."""

# Tool schemas handed to the model so it must emit structured actions.
RED_TOOL = {
    "name": "red_action",
    "description": "Choose one Red Team action for this turn.",
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {"type": "string",
                       "enum": [t.value for t in RedActionType]},
            "target": {"type": "string", "description": "Node name the action targets."},
            "source": {"type": "string",
                       "description": "For LATERAL_MOVE: the foothold node to pivot from."},
            "rationale": {"type": "string", "description": "One sentence of reasoning."},
        },
        "required": ["action", "rationale"],
    },
}

BLUE_TOOL = {
    "name": "blue_action",
    "description": "Choose one Blue Team action for this turn.",
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {"type": "string",
                       "enum": [t.value for t in BlueActionType]},
            "target": {"type": "string", "description": "Node name the action targets."},
            "rationale": {"type": "string", "description": "One sentence of reasoning."},
        },
        "required": ["action", "rationale"],
    },
}


_warned: set = set()


def _warn_once(key: str, message: str) -> None:
    """Print a fallback reason once per process, so batch runs aren't flooded."""
    if key not in _warned:
        _warned.add(key)
        print(f"[llm] {message}")


def _call_claude(system: str, user_text: str, tool: dict, model: str) -> Optional[dict]:
    """Return the tool-call input dict, or None if the call/SDK is unavailable."""
    try:
        import anthropic  # lazy import so offline/mock use needs no install
    except ImportError:
        _warn_once("sdk", "--live needs `pip install anthropic`; falling back to heuristic.")
        return None
    try:
        # Credentials resolve from ANTHROPIC_API_KEY or any other SDK-supported source.
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model=model,
            max_tokens=400,
            system=system,
            tools=[tool],
            tool_choice={"type": "tool", "name": tool["name"]},
            messages=[{"role": "user", "content": user_text}],
        )
    except Exception as exc:  # network/auth/rate-limit — degrade gracefully
        _warn_once(type(exc).__name__,
                   f"Claude call failed ({exc}); falling back to heuristic.")
        return None
    if resp.stop_reason == "refusal":
        _warn_once("refusal", "Claude declined a turn (stop_reason=refusal); "
                              "falling back to heuristic.")
        return None
    for block in resp.content:
        if getattr(block, "type", None) == "tool_use":
            return dict(block.input)
    return None


def _prompt_from_view(view: dict, faction: Faction) -> str:
    who = "RED (attacker)" if faction is Faction.RED else "BLUE (defender)"
    return (f"You are {who}. Current turn: {view['step']}.\n\n"
            f"State you can see:\n{json.dumps(view, indent=2)}\n\n"
            "Call the action tool with your single best move for this turn.")


class LLMRed(RedAgent):
    def __init__(self, mock: bool = True, model: str = DEFAULT_MODEL):
        self.mock = mock
        self.model = model
        self._fallback = HeuristicRed()
        self.last_prompt = ""
        self.fallbacks = 0  # live turns decided by the heuristic brain instead

    def act(self, red_view: dict) -> Action:
        self.last_prompt = _prompt_from_view(red_view, Faction.RED)
        if not self.mock:
            result = _call_claude(RED_SYSTEM, self.last_prompt, RED_TOOL, self.model)
            if result:
                params = {}
                if result.get("target"):
                    params["target"] = result["target"]
                if result.get("source"):
                    params["source"] = result["source"]
                return Action(Faction.RED, result["action"], params,
                              result.get("rationale", ""))
            self.fallbacks += 1
        # mock mode, or the call failed: use the heuristic brain.
        action = self._fallback.act(red_view)
        action.rationale = f"[mock-llm] {action.rationale}"
        return action


class LLMBlue(BlueAgent):
    def __init__(self, mock: bool = True, model: str = DEFAULT_MODEL):
        self.mock = mock
        self.model = model
        self._fallback = HeuristicBlue()
        self.last_prompt = ""
        self.fallbacks = 0  # live turns decided by the heuristic brain instead

    def reset(self) -> None:
        self._fallback.reset()

    def act(self, blue_view: dict) -> Action:
        self.last_prompt = _prompt_from_view(blue_view, Faction.BLUE)
        if not self.mock:
            result = _call_claude(BLUE_SYSTEM, self.last_prompt, BLUE_TOOL, self.model)
            if result:
                params = {}
                if result.get("target"):
                    params["target"] = result["target"]
                return Action(Faction.BLUE, result["action"], params,
                              result.get("rationale", ""))
            self.fallbacks += 1
        action = self._fallback.act(blue_view)
        action.rationale = f"[mock-llm] {action.rationale}"
        return action
