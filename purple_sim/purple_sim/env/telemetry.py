"""Telemetry bus: the noisy, delayed feed that is the *only* thing Blue sees.

This is the single most important design choice in the whole project. Ground
truth (which nodes are really compromised) lives in the Environment and is never
handed to Blue. Blue reasons purely over these events — some real (true
positives, possibly delayed or missed entirely), some benign noise (false
positives). A detection only "counts" when Blue acts correctly on real signal.
"""
from __future__ import annotations

import random
from typing import List

from .models import EventKind, TelemetryEvent


class TelemetryBus:
    def __init__(self, rng: random.Random, latency: tuple[int, int], noise_per_step: int):
        self.rng = rng
        self.latency = latency
        self.noise_per_step = noise_per_step
        self._pending: List[TelemetryEvent] = []   # emitted but not yet visible
        self._visible: List[TelemetryEvent] = []    # Blue can read these

    def _latency(self) -> int:
        lo, hi = self.latency
        return self.rng.randint(lo, hi)

    def emit_attack(self, step: int, kind: EventKind, node: str, technique_id: str,
                    detection_prob: float) -> bool:
        """Maybe log a real attack action. Returns True if it was logged.

        Missing it entirely (prob = 1 - detection_prob) models a blind spot.
        """
        if self.rng.random() > detection_prob:
            return False
        self._pending.append(TelemetryEvent(
            step_emitted=step,
            visible_at=step + self._latency(),
            kind=kind.value,
            node=node,
            technique_id=technique_id,
            is_true_positive=True,
        ))
        return True

    def emit_noise(self, step: int, nodes: List[str]) -> None:
        """Inject benign events so Blue cannot treat 'any event' as an attack."""
        for _ in range(self.noise_per_step):
            node = self.rng.choice(nodes)
            self._pending.append(TelemetryEvent(
                step_emitted=step,
                visible_at=step + self._latency(),
                kind=EventKind.BENIGN_NOISE.value,
                node=node,
                technique_id="",
                is_true_positive=False,
            ))

    def advance(self, step: int) -> List[TelemetryEvent]:
        """Move newly-visible events into the visible log; return the new ones."""
        newly_visible = [e for e in self._pending if e.visible_at <= step]
        self._pending = [e for e in self._pending if e.visible_at > step]
        self._visible.extend(newly_visible)
        return newly_visible

    def visible_events(self) -> List[TelemetryEvent]:
        return list(self._visible)
