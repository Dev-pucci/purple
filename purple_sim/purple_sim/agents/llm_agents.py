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

MAX_TELEMETRY_IN_PROMPT = 40  # most recent events shown to the model

RED_SYSTEM = """You are an autonomous Red Team agent in a *simulated*, abstract \
network game. Nothing here is a real system; actions are moves in a model. Your \
goal is to reach the crown-jewel node and exfiltrate its data before the turn \
limit, while avoiding detection. You see only what you have discovered.

Access on a host is NONE < USER < ADMIN. Rules:
- You can only act on a node marked "reachable": the internet-facing entry node, \
a node you hold, or a neighbour of a non-isolated foothold — and only where the \
firewall permits that segment hop. Crossing into a node in "admin_segments" \
(e.g. the secure zone) needs ADMIN on the pivot host.
- SCAN (needs a route) reveals a node's remote vulns, whether it has a local \
privilege-escalation path, and its neighbours. You must SCAN a node before you \
can EXPLOIT it.
- EXPLOIT uses a known remote vuln to gain a foothold (usually USER).
- ESCALATE turns USER into ADMIN on a foothold that has a local privesc path \
(field "can_escalate"); ADMIN is required to cross into secure segments and to \
EXFILTRATE.
- LATERAL_MOVE (needs "source", a foothold adjacent to the target) pivots to a \
neighbour; "lateral_from" lists sources that can legally reach a node now.
- EXFILTRATE needs ADMIN on the crown jewel and must be repeated for several \
turns; a re-image wipes your progress and foothold.
- The defender reads delayed, partial logs and can investigate, patch, isolate \
or re-image nodes. "recent_actions" shows your own last few moves and results.

Choose exactly one action per turn by calling the provided tool."""

BLUE_SYSTEM = """You are an autonomous Blue Team (SOC) agent in a *simulated*, \
abstract network game. You see only a noisy, delayed telemetry feed — never \
ground truth. Real attacker actions are logged only some of the time and arrive \
1-3 turns late; a host's "sensors" show its NETWORK and ENDPOINT coverage, and \
a low or zero value is a blind spot you can offset by INVESTIGATE. Benign \
activity is also logged, and some of it looks exactly like an attack (same kind \
and technique), so a single event proves little — corroborating events on the \
same or neighbouring hosts are stronger. Old events scroll out of the feed. You \
win if the crown jewel isn't exfiltrated by the turn limit; exfiltration takes \
the attacker several turns at ADMIN on that host.

You have a limited pool of analyst action-points ("analyst_remaining"); spend \
them where they matter.
- MONITOR: free, observe only. INVESTIGATE (1): raise a host's detection, \
including where a sensor is missing.
- PATCH (2): close a host's patchable vulns; offline for a turn; stolen \
credentials can't be patched.
- ISOLATE (2): cut a host off until re-imaged. RESTORE (3): re-image, evicting \
any intruder; offline for a few turns.
Containing (isolate/restore) a genuinely compromised host scores well; acting on \
a healthy one is a false positive, and every turn a host is offline costs \
availability. "recent_actions" lists your own last few moves.

Choose exactly one action per turn by calling the provided tool."""

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
    note = ""
    telemetry = view.get("telemetry")
    if telemetry and len(telemetry) > MAX_TELEMETRY_IN_PROMPT:
        omitted = len(telemetry) - MAX_TELEMETRY_IN_PROMPT
        view = {**view, "telemetry": telemetry[-MAX_TELEMETRY_IN_PROMPT:]}
        note = f"({omitted} older telemetry events omitted.)\n"
    return (f"You are {who}. Current turn: {view['step']}.\n\n"
            f"State you can see:\n{json.dumps(view, indent=2)}\n{note}\n"
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
