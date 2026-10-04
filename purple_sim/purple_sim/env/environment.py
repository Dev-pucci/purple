"""The Environment: shared game state + turn resolution.

Keeps ground truth private. Exposes two partial *views*:
  - red_view()  : what Red has discovered (scanned nodes, found vulns, footholds)
  - blue_view() : the telemetry feed + the availability it can observe

A turn is: resolve Red's action -> tick restores -> emit noise + advance the
bus -> Blue reads its view and acts -> resolve Blue's action. Blue therefore
sees every event whose latency has elapsed *this* step. Scoring is handled by
the Scorer (see scoring/), from ground truth recorded on each StepResult.

Movement rules:
  - Red can only touch a node it has a *route* to: the internet-facing entry
    node, a node it already holds, or a neighbour of a foothold it holds that
    is not isolated. Discovery alone is not enough.
  - An isolated node is cut off: it can't be scanned, exploited or pivoted
    into, and a Red foothold on it can't be pivoted from or exfiltrated from.
  - A re-imaging (RESTORE) node is offline for `restore_duration` Red turns,
    then comes back clean and un-isolated.
  - EXFILTRATE takes `exfil_steps` turns on the crown jewel; a re-image wipes
    the progress.
  - PATCH closes a node's patchable vulnerabilities but takes it offline for
    `patch_duration` Red turns (a maintenance window). Some vulnerabilities
    (stolen credentials) can't be patched at all.

Randomness comes from three independent streams (Red's action outcomes,
telemetry detection/latency, benign noise), so two agents run on the same
seed face the same luck wherever their choices coincide.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Union

from .models import (Action, BlueActionType, EventKind, Faction, Node,
                     RedActionType, TelemetryEvent)
from .scenario import DEFAULT_CONFIG, make_network
from .telemetry import TelemetryBus

BlueInput = Union[Action, Callable[[dict], Action]]

HISTORY_IN_VIEW = 5  # how many of its own recent moves each side sees


@dataclass
class StepResult:
    step: int
    red_action: Optional[Action]
    blue_action: Optional[Action]
    red_outcome: str = ""
    blue_outcome: str = ""
    new_events: List[TelemetryEvent] = field(default_factory=list)
    done: bool = False
    red_feedback: str = ""            # what Red itself learns (no telemetry hints)

    # --- ground truth recorded for scoring (never shown to Blue) -------------
    red_executed: bool = False        # Red's action actually reached the network
    red_technique: str = ""           # ATT&CK technique Red actually used
    red_compromised: str = ""         # node Red newly compromised this step
    blue_target_compromised: bool = False  # was Blue's target compromised when Blue acted?
    blue_effective: bool = False      # did Blue's action change anything?
    undetected_footholds: int = 0     # Red footholds with no true-positive telemetry visible yet
    offline_nodes: int = 0            # nodes isolated or re-imaging at end of step


@dataclass
class RedKnowledge:
    """Red's private memory of what it has learned about the network."""
    discovered: set = field(default_factory=set)       # node names Red can see
    known_vulns: Dict[str, List[str]] = field(default_factory=dict)  # node -> [cve_label]
    footholds: set = field(default_factory=set)         # compromised node names Red holds


class Environment:
    def __init__(self, network: Optional[Dict[str, Node]] = None,
                 config: Optional[dict] = None):
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        seed = self.config["seed"]
        self.nodes: Dict[str, Node] = network or make_network(self.config["scenario"], seed)
        self.rng = random.Random(f"{seed}:red")  # Red action outcomes
        self.bus = TelemetryBus(
            rng=random.Random(f"{seed}:telemetry"),
            latency=tuple(self.config["telemetry_latency"]),
            noise_per_step=self.config["noise_per_step"],
            noise_rng=random.Random(f"{seed}:noise"),
            lookalike_prob=self.config["lookalike_prob"],
        )
        self.step_count = 0
        self.max_steps = self.config["max_steps"]
        self.done = False
        self.winner: Optional[str] = None
        self.termination_reason = ""
        self.red_exfiltrated = False
        self.red = RedKnowledge()
        self.history: List[StepResult] = []
        self._compromised_at: Dict[str, int] = {}  # node -> step Red last took it
        self.exfil_progress: Dict[str, int] = {}   # node -> EXFILTRATE turns completed

        # Red always starts knowing the internet-facing entry node exists.
        for name, node in self.nodes.items():
            if node.is_entry:
                self.red.discovered.add(name)

    # ------------------------------------------------------------------ helpers
    def entry_node(self) -> str:
        for name, node in self.nodes.items():
            if node.is_entry:
                return name
        return next(iter(self.nodes))

    def crown_jewel(self) -> Optional[str]:
        for name, node in self.nodes.items():
            if node.is_crown_jewel:
                return name
        return None

    def offline(self, name: str) -> bool:
        node = self.nodes[name]
        return node.isolated or node.restoring > 0 or node.patching > 0

    def _has_route(self, name: str) -> bool:
        """Red has a network path to `name` (ignoring whether `name` itself is up)."""
        if name not in self.nodes:
            return False
        if self.nodes[name].is_entry or name in self.red.footholds:
            return True
        return any(name in self.nodes[f].connections and not self.offline(f)
                   for f in self.red.footholds)

    def reachable(self, name: str) -> bool:
        """Red can act on `name` this turn."""
        return self._has_route(name) and not self.offline(name)

    def _node_technique(self, node: Node) -> str:
        return node.vulnerabilities[0].technique_id if node.vulnerabilities else "T1190"

    def _compromise(self, name: str, rec: StepResult) -> None:
        self.nodes[name].compromised = True
        self.red.footholds.add(name)
        self._compromised_at[name] = self.step_count
        rec.red_compromised = name

    # ------------------------------------------------------------------- views
    def red_view(self) -> dict:
        """What Red knows — discovered nodes only, with its own footholds."""
        view = {"step": self.step_count, "nodes": {}, "footholds": sorted(self.red.footholds)}
        for name in sorted(self.red.discovered):
            node = self.nodes[name]
            view["nodes"][name] = {
                "services": node.services,
                "connections": node.connections,
                "is_crown_jewel": node.is_crown_jewel,
                "compromised_by_me": name in self.red.footholds,
                "isolated": node.isolated,
                "reachable": self.reachable(name),
                "scanned": name in self.red.known_vulns,
                "known_vulns": self.red.known_vulns.get(name, []),
            }
        view["recent_actions"] = [
            {"step": r.step, "action": str(r.red_action), "result": r.red_feedback}
            for r in self.history[-HISTORY_IN_VIEW:]]
        return view

    def blue_view(self) -> dict:
        """What Blue sees — telemetry + observable availability. No ground truth."""
        return {
            "step": self.step_count,
            "nodes": {
                name: {
                    "services": node.services,
                    "connections": node.connections,
                    "is_crown_jewel": node.is_crown_jewel,
                    "isolated": node.isolated,
                    "monitoring": round(node.monitoring, 2),
                    "restoring": node.restoring > 0,
                    "patching": node.patching > 0,
                }
                for name, node in self.nodes.items()
            },
            "telemetry": [e.as_blue_view() for e in self.bus.visible_events()],
            # Blue's own moves only — never their ground-truth outcome.
            "recent_actions": [{"step": r.step, "action": str(r.blue_action)}
                               for r in self.history[-HISTORY_IN_VIEW:]],
        }

    # --------------------------------------------------------------- resolution
    def _resolve_red(self, action: Action, rec: StepResult) -> str:
        a = action.type
        target = action.params.get("target", "")

        if a == RedActionType.WAIT.value:
            return "Red lies low (no action)."

        if a == RedActionType.SCAN.value:
            if target not in self.red.discovered:
                return f"SCAN failed: {target!r} not discovered yet."
            if not self._has_route(target):
                return f"SCAN failed: no route to {target!r} (need a foothold next to it)."
            node = self.nodes[target]
            rec.red_executed, rec.red_technique = True, "T1595"
            self.bus.emit_attack(self.step_count, EventKind.SCAN_DETECTED, target,
                                 "T1595", 0.2 + node.monitoring)
            if self.offline(target):
                return f"SCAN {target}: no response — node is isolated/offline."
            for neigh in node.connections:
                self.red.discovered.add(neigh)  # discover adjacency
            self.red.known_vulns[target] = [v.cve_label for v in node.open_vulns()]
            return f"SCAN {target}: found {len(self.red.known_vulns[target])} vuln(s), "\
                   f"revealed neighbours {node.connections}."

        if a == RedActionType.EXPLOIT.value:
            if target not in self.red.discovered:
                return f"EXPLOIT failed: {target!r} not discovered yet."
            if not self._has_route(target):
                return f"EXPLOIT failed: no route to {target!r} (need a foothold next to it)."
            node = self.nodes[target]
            vulns = node.open_vulns()
            if self.offline(target) or not vulns:
                tech = self._node_technique(node)
                rec.red_executed, rec.red_technique = True, tech
                self.bus.emit_attack(self.step_count, EventKind.EXPLOIT_ATTEMPT, target,
                                     tech, 0.6 + node.monitoring)
                if self.offline(target):
                    return f"EXPLOIT {target}: blocked — node is isolated/offline."
                self.red.known_vulns[target] = []  # Red learns it's been patched
                return f"EXPLOIT {target}: no open vulnerabilities (patched)."
            vuln = max(vulns, key=lambda v: v.success_prob)
            rec.red_executed, rec.red_technique = True, vuln.technique_id
            logged = self.bus.emit_attack(self.step_count, EventKind.EXPLOIT_ATTEMPT,
                                          target, vuln.technique_id,
                                          vuln.detection_prob + node.monitoring)
            if self.rng.random() <= vuln.success_prob:
                self._compromise(target, rec)
                rec.red_feedback = f"EXPLOIT {target} via {vuln.technique_id}: SUCCESS."
                seen = " (telemetry logged)" if logged else " (undetected)"
                return f"EXPLOIT {target} via {vuln.technique_id}: SUCCESS{seen}."
            return f"EXPLOIT {target} via {vuln.technique_id}: attempt failed."

        if a == RedActionType.LATERAL_MOVE.value:
            # Credentialed pivot (T1021): works even on patched hosts, but less reliably.
            src = action.params.get("source", "")
            if src not in self.red.footholds:
                return f"LATERAL_MOVE failed: no foothold on source {src!r}."
            if self.offline(src):
                return f"LATERAL_MOVE failed: source {src!r} is isolated/offline."
            if target not in self.nodes[src].connections:
                return f"LATERAL_MOVE failed: {target!r} not adjacent to {src!r}."
            if target in self.red.footholds:
                return f"LATERAL_MOVE failed: already hold {target!r}."
            self.red.discovered.add(target)
            node = self.nodes[target]
            rec.red_executed, rec.red_technique = True, "T1021"
            self.bus.emit_attack(self.step_count, EventKind.LATERAL_DETECTED, target,
                                 "T1021", self.config["lateral_detection"] + node.monitoring)
            if self.offline(target):
                return f"LATERAL_MOVE {src}->{target}: blocked — node is isolated/offline."
            if self.rng.random() <= self.config["lateral_success"]:
                self._compromise(target, rec)
                return f"LATERAL_MOVE {src}->{target}: SUCCESS, now hold {target}."
            return f"LATERAL_MOVE {src}->{target}: credentials rejected."

        if a == RedActionType.EXFILTRATE.value:
            if target not in self.red.footholds:
                return f"EXFILTRATE failed: {target!r} not compromised."
            node = self.nodes[target]
            if not node.is_crown_jewel:
                return f"EXFILTRATE {target}: nothing valuable here."
            rec.red_executed, rec.red_technique = True, "T1048"
            self.bus.emit_attack(self.step_count, EventKind.EXFIL_DETECTED, target,
                                 "T1048", self.config["exfil_detection"] + node.monitoring)
            if self.offline(target):
                return f"EXFILTRATE {target}: blocked — node is isolated/offline."
            # Pulling a database out takes several turns; progress is lost on eviction.
            self.exfil_progress[target] = self.exfil_progress.get(target, 0) + 1
            needed = self.config["exfil_steps"]
            if self.exfil_progress[target] < needed:
                return f"EXFILTRATE {target}: transferring data "\
                       f"({self.exfil_progress[target]}/{needed})."
            self.red_exfiltrated = True
            return f"EXFILTRATE {target}: CROWN JEWEL DATA STOLEN."

        return f"Unknown Red action {a!r}."

    def _resolve_blue(self, action: Action, rec: StepResult) -> str:
        a = action.type
        target = action.params.get("target", "")

        if a == BlueActionType.MONITOR.value:
            return "Blue monitors (passive)."

        if a not in {t.value for t in BlueActionType}:
            return f"Unknown Blue action {a!r}."
        if target not in self.nodes:
            return f"{a} failed: {target!r} unknown."
        node = self.nodes[target]
        rec.blue_target_compromised = node.compromised

        if a == BlueActionType.INVESTIGATE.value:
            before = node.monitoring
            node.monitoring = min(1.0, node.monitoring + self.config["investigate_boost"])
            rec.blue_effective = node.monitoring > before
            return f"INVESTIGATE {target}: monitoring raised to {node.monitoring:.2f}."

        if a == BlueActionType.ISOLATE.value:
            if node.isolated:
                return f"ISOLATE {target}: already isolated (no-op)."
            node.isolated = True
            rec.blue_effective = True
            return f"ISOLATE {target}: node cut off (availability impact)."

        if a == BlueActionType.PATCH.value:
            vulns = node.patchable_vulns()
            if not vulns or node.patching > 0:
                return f"PATCH {target}: nothing to patch (no-op)."
            for v in vulns:
                v.patched = True
            node.patching = max(node.patching, self.config["patch_duration"])
            rec.blue_effective = True
            return f"PATCH {target}: {len(vulns)} vulnerability(ies) closed "\
                   f"(maintenance window)."

        if a == BlueActionType.RESTORE.value:
            if node.restoring > 0:
                return f"RESTORE {target}: already re-imaging (no-op)."
            node.restoring = self.config["restore_duration"]
            was_compromised = node.compromised
            node.compromised = False
            self.red.footholds.discard(target)
            self.exfil_progress.pop(target, None)
            rec.blue_effective = True
            tag = "evicted active intruder" if was_compromised else "no intruder found (wasted)"
            return f"RESTORE {target}: re-imaging ({tag})."

        return f"Unknown Blue action {a!r}."

    def _tick_restores(self) -> None:
        for node in self.nodes.values():
            if node.patching > 0:
                node.patching -= 1
            if node.restoring > 0:
                node.restoring -= 1
                if node.restoring == 0:
                    node.isolated = False  # back in service from a clean image

    def _undetected_footholds(self) -> int:
        """Footholds with no true-positive event visible since Red took them."""
        seen_since: Dict[str, int] = {}
        for e in self.bus.visible_events():
            if e.is_true_positive:
                seen_since[e.node] = max(seen_since.get(e.node, -1), e.step_emitted)
        return sum(1 for f in self.red.footholds
                   if seen_since.get(f, -1) < self._compromised_at.get(f, 0))

    # -------------------------------------------------------------------- step
    def step(self, red_action: Action, blue: BlueInput) -> StepResult:
        """Advance one turn.

        `blue` is either a fixed Action or a policy `f(blue_view) -> Action`.
        Pass a policy to have Blue decide on the telemetry visible *this* step.
        """
        if self.done:
            raise RuntimeError("Simulation already finished.")
        self.step_count += 1
        rec = StepResult(step=self.step_count, red_action=red_action, blue_action=None)

        rec.red_outcome = self._resolve_red(red_action, rec)
        rec.red_feedback = rec.red_feedback or rec.red_outcome
        self._tick_restores()
        self.bus.emit_noise(self.step_count, {name: self._node_technique(node)
                                              for name, node in self.nodes.items()})
        rec.new_events = self.bus.advance(self.step_count)

        blue_action = blue(self.blue_view()) if callable(blue) else blue
        rec.blue_action = blue_action
        rec.blue_outcome = self._resolve_blue(blue_action, rec)

        rec.undetected_footholds = self._undetected_footholds()
        rec.offline_nodes = sum(1 for n in self.nodes if self.offline(n))

        # termination
        if self.red_exfiltrated:
            self.done = True
            self.winner = Faction.RED.value
            self.termination_reason = "Red exfiltrated the crown jewel."
        elif self.step_count >= self.max_steps:
            self.done = True
            self.winner = Faction.BLUE.value
            self.termination_reason = "Max steps reached without exfiltration."

        rec.done = self.done
        self.history.append(rec)
        return rec
