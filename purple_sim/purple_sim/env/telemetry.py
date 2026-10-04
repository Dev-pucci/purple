"""Telemetry bus: the noisy, delayed feed that is the *only* thing Blue sees.

This is the single most important design choice in the whole project. Ground
truth (which hosts Red really controls) lives in the Environment and is never
handed to Blue. Blue reasons purely over these events — some real (true
positives, possibly delayed or missed entirely), some benign noise (false
positives). Some of that noise is *look-alike*: benign activity carrying an
attack-shaped event kind, so Blue can't filter false positives by kind alone.

Each event is produced by a sensor (NETWORK or ENDPOINT). A host can be strong
on one sensor and blind on the other, so whether a real action is logged
depends on the host's coverage for that sensor — the Environment folds that in
before calling `emit_attack`. Blue only acts on events inside a retention
window; older ones scroll off its working view (but stay in the record the
Purple report is scored against).
"""
from __future__ import annotations

import random
from typing import Dict, List, Optional

from .models import LOOKALIKE_NOISE, EVENT_SENSOR, EventKind, Sensor, TelemetryEvent

# Technique a look-alike event of each kind carries (exploit look-alikes use the
# host's own technique, supplied by the Environment, so they can't be told apart).
_LOOKALIKE_TECHNIQUE = {EventKind.SCAN_DETECTED: "T1595",
                        EventKind.LATERAL_DETECTED: "T1021",
                        EventKind.PRIVESC_DETECTED: "T1068"}


class TelemetryBus:
    def __init__(self, rng: random.Random, latency: tuple[int, int], noise_per_step: int,
                 noise_rng: Optional[random.Random] = None, lookalike_prob: float = 0.0,
                 retention: int = 0):
        self.rng = rng                      # detection + latency rolls for real events
        self.noise_rng = noise_rng or rng   # benign noise draws from its own stream
        self.latency = latency
        self.noise_per_step = noise_per_step
        self.lookalike_prob = lookalike_prob
        self.retention = retention          # 0 = keep everything in Blue's working view
        self._pending: List[TelemetryEvent] = []   # emitted but not yet visible
        self._visible: List[TelemetryEvent] = []    # the full visible record

    def _latency(self, rng: random.Random) -> int:
        lo, hi = self.latency
        return rng.randint(lo, hi)

    def emit_attack(self, step: int, kind: EventKind, node: str, technique_id: str,
                    detection_prob: float) -> bool:
        """Maybe log a real attack action. Returns True if it was logged.

        `detection_prob` is already folded with the host's sensor coverage and
        Blue's monitoring. Missing it entirely models a blind spot.
        """
        if self.rng.random() > detection_prob:
            return False
        self._pending.append(TelemetryEvent(
            step_emitted=step,
            visible_at=step + self._latency(self.rng),
            kind=kind.value,
            node=node,
            technique_id=technique_id,
            sensor=EVENT_SENSOR[kind].value,
            is_true_positive=True,
        ))
        return True

    def emit_noise(self, step: int, exploit_techniques: Dict[str, str]) -> None:
        """Inject benign events so Blue cannot treat 'any event' as an attack.

        `exploit_techniques` maps every node to the technique an exploit
        look-alike on that node should carry.
        """
        rng = self.noise_rng
        nodes = list(exploit_techniques)
        kinds = list(LOOKALIKE_NOISE)
        weights = list(LOOKALIKE_NOISE.values())
        for _ in range(self.noise_per_step):
            node = rng.choice(nodes)
            kind, technique, sensor = EventKind.BENIGN_NOISE, "", ""
            if rng.random() < self.lookalike_prob:
                kind = rng.choices(kinds, weights)[0]
                technique = _LOOKALIKE_TECHNIQUE.get(kind, exploit_techniques[node])
                sensor = EVENT_SENSOR[kind].value
            self._pending.append(TelemetryEvent(
                step_emitted=step,
                visible_at=step + self._latency(rng),
                kind=kind.value,
                node=node,
                technique_id=technique,
                sensor=sensor,
                is_true_positive=False,
            ))

    def advance(self, step: int) -> List[TelemetryEvent]:
        """Move newly-visible events into the visible log; return the new ones."""
        newly_visible = [e for e in self._pending if e.visible_at <= step]
        self._pending = [e for e in self._pending if e.visible_at > step]
        self._visible.extend(newly_visible)
        return newly_visible

    def visible_events(self) -> List[TelemetryEvent]:
        """The full record of everything that ever became visible (for scoring)."""
        return list(self._visible)

    def working_events(self, step: int) -> List[TelemetryEvent]:
        """What Blue can act on now: visible and within the retention window."""
        if self.retention <= 0:
            return list(self._visible)
        return [e for e in self._visible if step - e.step_emitted < self.retention]
