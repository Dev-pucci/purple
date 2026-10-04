"""The Environment: shared game state + turn resolution.

Keeps ground truth private. Exposes two partial *views*:
  - red_view()  : what Red has discovered (scanned nodes, vulns, its own access)
  - blue_view() : the telemetry feed + the availability/sensors it can observe

A turn is: resolve Red's action -> tick restores/patches -> emit noise + advance
the bus -> Blue reads its view and acts -> resolve Blue's action. Blue sees
every event whose latency has elapsed *this* step. Scoring is handled by the
Scorer (see scoring/), from ground truth recorded on each StepResult.

Attack model (abstract — no real systems or exploit code):
  - Access is NONE < USER < ADMIN. EXPLOIT of a known remote vuln yields a
    foothold (usually USER); ESCALATE uses a local vuln to go USER -> ADMIN.
  - Red can only act on a node it has a *route* to: the internet-facing entry
    node, a node it holds, or a neighbour of a non-isolated foothold — and only
    where the firewall allows that segment hop. Crossing into an ADMIN_SEGMENT
    (e.g. `secure`) needs ADMIN on the source.
  - EXPLOIT needs a prior SCAN (you can't exploit what you haven't fingerprinted).
  - EXFILTRATE needs ADMIN on the crown jewel and takes `exfil_steps` turns; a
    re-image wipes the progress.
  - Isolated / re-imaging / patching nodes are offline and can't be acted on.

Detection:
  - Each attack action would be logged by one sensor (NETWORK or ENDPOINT). The
    chance is the action's base detection times the host's coverage for that
    sensor, plus Blue's INVESTIGATE monitoring (which works even where a sensor
    is absent). A zero-coverage sensor is a blind spot.

Defender budget:
  - Blue has a finite pool of analyst action-points for the whole game; active
    actions cost points and do nothing once the pool is empty.

Randomness comes from three independent streams (Red outcomes, telemetry
detection/latency, benign noise), so two agents on the same seed face the same
luck wherever their choices coincide.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Union

from .models import (Action, AccessLevel, BlueActionType, EVENT_SENSOR, EventKind,
                     Faction, Node, RedActionType, TelemetryEvent)
from .scenario import ADMIN_SEGMENTS, DEFAULT_CONFIG, FIREWALL, make_network
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
    red_compromised: str = ""         # node Red newly gained a foothold on this step
    blue_target_compromised: bool = False  # was Blue's target compromised when Blue acted?
    blue_effective: bool = False      # did Blue's action change anything?
    undetected_footholds: int = 0     # footholds with no true-positive telemetry visible yet
    offline_nodes: int = 0            # nodes offline (isolated/re-imaging/patching) at step end


@dataclass
class RedKnowledge:
    """Red's private memory of what it has learned about the network."""
    discovered: set = field(default_factory=set)       # node names Red can see
    known_vulns: Dict[str, List[str]] = field(default_factory=dict)  # node -> [remote cve_label]
    known_local: Dict[str, bool] = field(default_factory=dict)       # node -> local privesc seen
    footholds: set = field(default_factory=set)         # nodes Red holds (access >= USER)


class Environment:
    def __init__(self, network: Optional[Dict[str, Node]] = None,
                 config: Optional[dict] = None, firewall: Optional[Dict[str, set]] = None):
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        seed = self.config["seed"]
        self.nodes: Dict[str, Node] = network or make_network(self.config["scenario"], seed)
        # A custom network with no firewall given gets an allow-all policy (None).
        self.firewall = firewall if firewall is not None else (
            FIREWALL if network is None else None)
        self.rng = random.Random(f"{seed}:red")
        self.bus = TelemetryBus(
            rng=random.Random(f"{seed}:telemetry"),
            latency=tuple(self.config["telemetry_latency"]),
            noise_per_step=self.config["noise_per_step"],
            noise_rng=random.Random(f"{seed}:noise"),
            lookalike_prob=self.config["lookalike_prob"],
            retention=self.config["log_retention"],
        )
        self.step_count = 0
        self.max_steps = self.config["max_steps"]
        self.done = False
        self.winner: Optional[str] = None
        self.termination_reason = ""
        self.red_exfiltrated = False
        self.red = RedKnowledge()
        self.history: List[StepResult] = []
        self.analyst_remaining = self.config["analyst_budget"]
        self._compromised_at: Dict[str, int] = {}  # node -> step Red last took it
        self.exfil_progress: Dict[str, int] = {}   # node -> EXFILTRATE turns completed

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

    def _fw_allows(self, src_segment: str, dst_segment: str) -> bool:
        if self.firewall is None:
            return True
        return dst_segment in self.firewall.get(src_segment, set())

    def _has_route(self, name: str) -> bool:
        """Red has a network path to `name` (ignoring whether `name` itself is up).

        Crossing into an ADMIN_SEGMENT needs the adjacent foothold to hold ADMIN
        (stolen domain creds), so scan/exploit/lateral into `secure` all require
        a prior ESCALATE on the pivot host.
        """
        if name not in self.nodes:
            return False
        node = self.nodes[name]
        if name in self.red.footholds:
            return True
        if node.is_entry and self._fw_allows("internet", node.segment):
            return True
        needs_admin = node.segment in ADMIN_SEGMENTS
        return any(name in self.nodes[f].connections and not self.offline(f)
                   and self._fw_allows(self.nodes[f].segment, node.segment)
                   and (not needs_admin or self.nodes[f].access >= AccessLevel.ADMIN)
                   for f in self.red.footholds)

    def reachable(self, name: str) -> bool:
        """Red can act on `name` this turn."""
        return self._has_route(name) and not self.offline(name)

    def _lateral_sources(self, target: str) -> List[str]:
        """Footholds that could legally pivot to `target` this turn.

        Normally this means an adjacent, firewall-permitted foothold (ADMIN on
        it when crossing into a secure segment). But ADMIN on an *identity* host
        (a domain controller) yields domain-wide credentials: it can pivot to
        any domain-joined host (every non-entry node) without adjacency —
        modelling "own the DC, own the domain".
        """
        node = self.nodes[target]
        if target in self.red.footholds or self.offline(target):
            return []
        needs_admin = node.segment in ADMIN_SEGMENTS
        out = []
        for f in sorted(self.red.footholds):
            src = self.nodes[f]
            if self.offline(f):
                continue
            adjacent = (target in src.connections and self._fw_allows(src.segment, node.segment)
                        and (not needs_admin or src.access >= AccessLevel.ADMIN))
            domain = (src.is_identity and src.access >= AccessLevel.ADMIN
                      and not node.is_entry)
            if adjacent or domain:
                out.append(f)
        return out

    def _node_technique(self, node: Node) -> str:
        return node.vulnerabilities[0].technique_id if node.vulnerabilities else "T1190"

    def _emit(self, kind: EventKind, node: Node, technique: str, base: float) -> bool:
        """Log an attack action, folding in the host's sensor coverage + monitoring.

        A decoy (canary) on the host catches any Red activity reliably, whatever
        the sensor coverage — that is the point of a tripwire.
        """
        if node.decoy:
            prob = 1.0
        else:
            coverage = node.sensor_coverage(EVENT_SENSOR[kind].value)
            prob = min(1.0, base * coverage + node.monitoring)
        return self.bus.emit_attack(self.step_count, kind, node.name, technique, prob)

    def _grant(self, name: str, level: int, rec: StepResult) -> None:
        node = self.nodes[name]
        was_foothold = node.compromised
        node.access = max(node.access, level)
        if not was_foothold:
            self.red.footholds.add(name)
            self._compromised_at[name] = self.step_count
            rec.red_compromised = name

    # ------------------------------------------------------------------- views
    def red_view(self) -> dict:
        """What Red knows — discovered nodes only, with its own access."""
        view = {"step": self.step_count, "max_steps": self.max_steps,
                "exfil_steps": self.config["exfil_steps"],
                "admin_segments": list(ADMIN_SEGMENTS), "nodes": {},
                "footholds": sorted(self.red.footholds)}
        for name in sorted(self.red.discovered):
            node = self.nodes[name]
            held = name in self.red.footholds
            offline = self.offline(name)
            view["nodes"][name] = {
                "services": node.services,
                "connections": node.connections,
                "segment": node.segment,
                "is_crown_jewel": node.is_crown_jewel,
                "is_identity": node.is_identity,
                "compromised_by_me": held,
                "access": int(node.access) if held else 0,
                "isolated": node.isolated,
                "offline": offline,
                "reachable": self.reachable(name),
                "scanned": name in self.red.known_vulns,
                "known_vulns": self.red.known_vulns.get(name, []),
                # A foothold below ADMIN can always attempt escalation (a known
                # local vuln, else the harder token-theft fallback).
                "can_escalate": held and not offline and node.access < AccessLevel.ADMIN,
                "lateral_from": self._lateral_sources(name),
                "exfil_progress": self.exfil_progress.get(name, 0),
            }
        view["recent_actions"] = [
            {"step": r.step, "action": str(r.red_action), "result": r.red_feedback}
            for r in self.history[-HISTORY_IN_VIEW:]]
        return view

    def blue_view(self) -> dict:
        """What Blue sees — telemetry + observable availability. No ground truth."""
        return {
            "step": self.step_count,
            "max_steps": self.max_steps,
            "analyst_remaining": self.analyst_remaining,
            "analyst_budget": self.config["analyst_budget"],
            "nodes": {
                name: {
                    "services": node.services,
                    "connections": node.connections,
                    "segment": node.segment,
                    "is_crown_jewel": node.is_crown_jewel,
                    "sensors": {s: round(c, 2) for s, c in node.sensors.items()},
                    "is_identity": node.is_identity,
                    "isolated": node.isolated,
                    "monitoring": round(node.monitoring, 2),
                    "restoring": node.restoring > 0,
                    "patching": node.patching > 0,
                    "decoy": node.decoy,
                }
                for name, node in self.nodes.items()
            },
            "telemetry": [e.as_blue_view() for e in self.bus.working_events(self.step_count)],
            "recent_actions": [{"step": r.step, "action": str(r.blue_action)}
                               for r in self.history[-HISTORY_IN_VIEW:]],
        }

    # --------------------------------------------------------------- resolution
    def _resolve_red(self, action: Action, rec: StepResult) -> str:
        a = action.type
        target = action.params.get("target", "")
        stealth = action.params.get("mode") == "stealth"
        succ_mult = self.config["stealth_success_mult"] if stealth else 1.0
        det_mult = self.config["stealth_detection_mult"] if stealth else 1.0

        if a == RedActionType.WAIT.value:
            return "Red lies low (no action)."

        if a == RedActionType.SCAN.value:
            if target not in self.red.discovered:
                return f"SCAN failed: {target!r} not discovered yet."
            if not self._has_route(target):
                return f"SCAN failed: no route to {target!r} (firewall or no adjacent foothold)."
            node = self.nodes[target]
            rec.red_executed, rec.red_technique = True, "T1595"
            self._emit(EventKind.SCAN_DETECTED, node, "T1595", 0.25)
            if self.offline(target):
                return f"SCAN {target}: no response — node is isolated/offline."
            for neigh in node.connections:
                self.red.discovered.add(neigh)
            self.red.known_vulns[target] = [v.cve_label for v in node.remote_vulns()]
            self.red.known_local[target] = bool(node.local_vulns())
            return (f"SCAN {target} [{node.segment}]: {len(self.red.known_vulns[target])} "
                    f"remote vuln(s), neighbours {node.connections}.")

        if a == RedActionType.EXPLOIT.value:
            if target not in self.red.discovered:
                return f"EXPLOIT failed: {target!r} not discovered yet."
            if not self._has_route(target):
                return f"EXPLOIT failed: no route to {target!r} (firewall or no adjacent foothold)."
            if target not in self.red.known_vulns:
                return f"EXPLOIT failed: SCAN {target} first to fingerprint it."
            node = self.nodes[target]
            vulns = node.remote_vulns()
            if self.offline(target) or not vulns:
                tech = self._node_technique(node)
                rec.red_executed, rec.red_technique = True, tech
                self._emit(EventKind.EXPLOIT_ATTEMPT, node, tech, 0.6)
                if self.offline(target):
                    return f"EXPLOIT {target}: blocked — node is isolated/offline."
                self.red.known_vulns[target] = []
                return f"EXPLOIT {target}: no open remote vulnerabilities (patched)."
            vuln = max(vulns, key=lambda v: v.success_prob)
            rec.red_executed, rec.red_technique = True, vuln.technique_id
            self._emit(EventKind.EXPLOIT_ATTEMPT, node, vuln.technique_id,
                       vuln.detection_prob * det_mult)
            if self.rng.random() <= vuln.success_prob * succ_mult:
                self._grant(target, vuln.grants, rec)
                lvl = AccessLevel(self.nodes[target].access).name
                how = " quietly" if stealth else ""
                rec.red_feedback = f"EXPLOIT {target} via {vuln.technique_id}: SUCCESS{how} ({lvl})."
                return rec.red_feedback
            return f"EXPLOIT {target} via {vuln.technique_id}: attempt failed."

        if a == RedActionType.ESCALATE.value:
            if target not in self.red.footholds:
                return f"ESCALATE failed: no foothold on {target!r}."
            node = self.nodes[target]
            if self.offline(target):
                return f"ESCALATE failed: {target!r} is isolated/offline."
            if node.access >= AccessLevel.ADMIN:
                return f"ESCALATE {target}: already ADMIN (no-op)."
            # A patched host still has a *harder* escalation path (token/credential
            # theft, T1134) that patching can't fully close — so patching raises
            # the bar but never permanently denies ADMIN. (Without this, patching
            # the crown jewel's one privesc vuln is a dominant, trivial defence —
            # a model single-point-of-failure the RL Blue discovered and exploited.)
            locals_ = node.local_vulns()
            if locals_:
                vuln = max(locals_, key=lambda v: v.success_prob)
                success, tech = vuln.success_prob, vuln.technique_id
            else:
                success, tech = self.config["escalate_fallback_success"], "T1134"
            rec.red_executed, rec.red_technique = True, tech
            self._emit(EventKind.PRIVESC_DETECTED, node, tech,
                       self.config["escalate_detection"] * det_mult)
            if self.rng.random() <= success * succ_mult:
                node.access = AccessLevel.ADMIN
                rec.red_feedback = f"ESCALATE {target} via {tech}: now ADMIN."
                return rec.red_feedback
            return f"ESCALATE {target} via {tech}: attempt failed."

        if a == RedActionType.LATERAL_MOVE.value:
            src = action.params.get("source", "")
            if src not in self.red.footholds:
                return f"LATERAL_MOVE failed: no foothold on source {src!r}."
            if target in self.red.footholds:
                return f"LATERAL_MOVE failed: already hold {target!r}."
            if target not in self.nodes:
                return f"LATERAL_MOVE failed: {target!r} unknown."
            src_node, node = self.nodes[src], self.nodes[target]
            if self.offline(src):
                return f"LATERAL_MOVE failed: source {src!r} is isolated/offline."
            # Domain credentials from an ADMIN identity host bypass adjacency and
            # the firewall (domain-joined hosts trust the DC).
            domain = (src_node.is_identity and src_node.access >= AccessLevel.ADMIN
                      and not node.is_entry)
            if not domain:
                if target not in src_node.connections:
                    return f"LATERAL_MOVE failed: {target!r} not adjacent to {src!r}."
                if not self._fw_allows(src_node.segment, node.segment):
                    return (f"LATERAL_MOVE failed: firewall blocks {src_node.segment}"
                            f"->{node.segment}.")
                if node.segment in ADMIN_SEGMENTS and src_node.access < AccessLevel.ADMIN:
                    return (f"LATERAL_MOVE failed: crossing into {node.segment} needs ADMIN "
                            f"on {src}.")
            self.red.discovered.add(target)
            rec.red_executed, rec.red_technique = True, "T1021"
            self._emit(EventKind.LATERAL_DETECTED, node, "T1021",
                       self.config["lateral_detection"] * det_mult)
            if self.offline(target):
                return f"LATERAL_MOVE {src}->{target}: blocked — node is isolated/offline."
            if self.rng.random() <= self.config["lateral_success"] * succ_mult:
                self._grant(target, AccessLevel.USER, rec)
                rec.red_feedback = f"LATERAL_MOVE {src}->{target}: SUCCESS, hold {target} (USER)."
                return rec.red_feedback
            return f"LATERAL_MOVE {src}->{target}: credentials rejected."

        if a == RedActionType.EXFILTRATE.value:
            if target not in self.red.footholds:
                return f"EXFILTRATE failed: {target!r} not compromised."
            node = self.nodes[target]
            if not node.is_crown_jewel:
                return f"EXFILTRATE {target}: nothing valuable here."
            if node.access < AccessLevel.ADMIN:
                return f"EXFILTRATE {target}: need ADMIN here first (ESCALATE)."
            rec.red_executed, rec.red_technique = True, "T1048"
            self._emit(EventKind.EXFIL_DETECTED, node, "T1048",
                       self.config["exfil_detection"] * det_mult)
            if self.offline(target):
                return f"EXFILTRATE {target}: blocked — node is isolated/offline."
            self.exfil_progress[target] = self.exfil_progress.get(target, 0) + 1
            needed = self.config["exfil_steps"]
            if self.exfil_progress[target] < needed:
                rec.red_feedback = (f"EXFILTRATE {target}: transferring "
                                    f"({self.exfil_progress[target]}/{needed}).")
                return rec.red_feedback
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

        budget_on = self.config["analyst_budget"] > 0
        cost = self.config["analyst_costs"].get(a, 0)
        if budget_on and self.analyst_remaining < cost:
            return f"{a} {target}: no analyst capacity (budget exhausted)."

        node = self.nodes[target]
        rec.blue_target_compromised = node.compromised
        outcome = self._apply_blue(a, target, node, rec)
        if rec.blue_effective and budget_on:
            self.analyst_remaining -= cost
        return outcome

    def _apply_blue(self, a: str, target: str, node: Node, rec: StepResult) -> str:
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
            return f"PATCH {target}: {len(vulns)} vulnerability(ies) closed (maintenance window)."

        if a == BlueActionType.RESTORE.value:
            if node.restoring > 0:
                return f"RESTORE {target}: already re-imaging (no-op)."
            node.restoring = self.config["restore_duration"]
            was_compromised = node.compromised
            node.access = AccessLevel.NONE
            self.red.footholds.discard(target)
            self.exfil_progress.pop(target, None)
            rec.blue_effective = True
            tag = "evicted active intruder" if was_compromised else "no intruder found (wasted)"
            return f"RESTORE {target}: re-imaging ({tag})."

        if a == BlueActionType.DECOY.value:
            if node.decoy:
                return f"DECOY {target}: canary already deployed (no-op)."
            node.decoy = True
            rec.blue_effective = True
            return f"DECOY {target}: canary deployed (Red activity here is caught reliably)."

        if a == BlueActionType.ROTATE_CREDS.value:
            # Revoke stolen admin credentials: Red keeps any USER foothold but
            # loses ADMIN (and, on an identity host, its domain-wide reach) until
            # it escalates again. Doesn't evict and costs no downtime.
            if node.access < AccessLevel.ADMIN:
                return f"ROTATE_CREDS {target}: nothing to revoke (no ADMIN here)."
            node.access = AccessLevel.USER
            rec.blue_effective = True
            extra = " (domain credentials revoked)" if node.is_identity else ""
            return f"ROTATE_CREDS {target}: admin credentials rotated{extra}."

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
        self.bus.emit_noise(self.step_count,
                            {name: self._node_technique(node) for name, node in self.nodes.items()},
                            {name: dict(node.sensors) for name, node in self.nodes.items()})
        rec.new_events = self.bus.advance(self.step_count)

        blue_action = blue(self.blue_view()) if callable(blue) else blue
        rec.blue_action = blue_action
        rec.blue_outcome = self._resolve_blue(blue_action, rec)

        rec.undetected_footholds = self._undetected_footholds()
        rec.offline_nodes = sum(1 for n in self.nodes if self.offline(n))

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
