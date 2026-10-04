"""Core data models for the simulation — plain stdlib dataclasses, no deps."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Dict, List, Optional


class Faction(str, Enum):
    RED = "RED"
    BLUE = "BLUE"


class AccessLevel(IntEnum):
    """How much control Red has on a host. Higher is strictly more capable."""
    NONE = 0
    USER = 1    # a foothold: can run code, pivot with USER-level reach
    ADMIN = 2   # full control: needed to cross into secure segments and to exfiltrate


class RedActionType(str, Enum):
    SCAN = "SCAN"              # discover a node's services/vulns + adjacent nodes
    EXPLOIT = "EXPLOIT"        # use a known remote vuln to gain a foothold
    ESCALATE = "ESCALATE"      # local privilege escalation USER -> ADMIN on a held node
    LATERAL_MOVE = "LATERAL_MOVE"  # pivot from a foothold to a neighbour
    EXFILTRATE = "EXFILTRATE"  # steal data from an ADMIN-held crown-jewel node
    WAIT = "WAIT"             # do nothing (lie low)


class BlueActionType(str, Enum):
    MONITOR = "MONITOR"        # cheap: just observe telemetry this turn
    INVESTIGATE = "INVESTIGATE"  # raise monitoring on a node (better future detection)
    ISOLATE = "ISOLATE"        # cut a node off: blocks exploit/lateral, hurts availability
    PATCH = "PATCH"            # remove a node's vulnerabilities (prevents exploit)
    RESTORE = "RESTORE"        # re-image a node: evicts Red if present, costs availability


# --- telemetry -----------------------------------------------------------------
class EventKind(str, Enum):
    SCAN_DETECTED = "SCAN_DETECTED"
    EXPLOIT_ATTEMPT = "EXPLOIT_ATTEMPT"
    PRIVESC_DETECTED = "PRIVESC_DETECTED"
    LATERAL_DETECTED = "LATERAL_DETECTED"
    EXFIL_DETECTED = "EXFIL_DETECTED"
    BENIGN_NOISE = "BENIGN_NOISE"


class Sensor(str, Enum):
    """Where an event would be seen. A node can be strong on one and blind on another."""
    NETWORK = "NETWORK"     # NIDS: network-visible actions (scans, lateral movement)
    ENDPOINT = "ENDPOINT"   # EDR: on-host actions (exploitation, privesc, exfil)


# Which sensor each attack event kind is picked up by.
EVENT_SENSOR = {
    EventKind.SCAN_DETECTED: Sensor.NETWORK,
    EventKind.LATERAL_DETECTED: Sensor.NETWORK,
    EventKind.EXPLOIT_ATTEMPT: Sensor.ENDPOINT,
    EventKind.PRIVESC_DETECTED: Sensor.ENDPOINT,
    EventKind.EXFIL_DETECTED: Sensor.ENDPOINT,
}

# Benign activity that *looks* like an attack (admin port scans, failed logins,
# legit remote sessions) — the false positives Blue has to reason about.
# kind -> relative frequency among look-alike events.
LOOKALIKE_NOISE = {
    EventKind.SCAN_DETECTED: 0.55,
    EventKind.EXPLOIT_ATTEMPT: 0.2,
    EventKind.LATERAL_DETECTED: 0.15,
    EventKind.PRIVESC_DETECTED: 0.1,
}


@dataclass
class Vulnerability:
    """An abstract weakness on a node. Not a real exploit — just a labelled flag."""
    technique_id: str          # MITRE ATT&CK id, e.g. "T1190"
    name: str                  # human label, e.g. "Exploit Public-Facing App"
    cve_label: str             # abstract vuln label, e.g. "CVE-SIM-0001"
    success_prob: float        # chance an attempt lands (0..1)
    detection_prob: float      # base chance the attempt shows up in telemetry (0..1)
    service: str = ""          # service it lives on, e.g. "http"
    grants: int = AccessLevel.USER    # access level a successful attempt yields
    local: bool = False        # True = local privesc (ESCALATE), needs a foothold first
    patched: bool = False
    patchable: bool = True     # False for e.g. stolen credentials: no patch fixes them


@dataclass
class Node:
    """A host on the abstract network."""
    name: str
    services: List[str] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    connections: List[str] = field(default_factory=list)  # adjacent node names
    value: int = 1             # reward weight for Red compromising this node
    is_crown_jewel: bool = False  # holds the data Red wants to exfiltrate
    is_entry: bool = False     # Red's starting foothold / internet-facing
    segment: str = "internal"  # network zone (firewall policy is between segments)
    sensors: Dict[str, float] = field(default_factory=dict)  # Sensor value -> coverage 0..1

    # --- ground-truth mutable state (only the Environment sees all of this) ---
    access: int = AccessLevel.NONE  # Red's current access on this host
    isolated: bool = False
    monitoring: float = 0.0    # extra detection probability added by Blue
    restoring: int = 0         # steps remaining in a RESTORE operation
    patching: int = 0          # steps remaining in a PATCH maintenance window

    @property
    def compromised(self) -> bool:
        return self.access >= AccessLevel.USER

    def sensor_coverage(self, sensor: str) -> float:
        return self.sensors.get(sensor, 0.0)

    def open_vulns(self) -> List[Vulnerability]:
        return [v for v in self.vulnerabilities if not v.patched]

    def remote_vulns(self) -> List[Vulnerability]:
        return [v for v in self.open_vulns() if not v.local]

    def local_vulns(self) -> List[Vulnerability]:
        return [v for v in self.open_vulns() if v.local]

    def patchable_vulns(self) -> List[Vulnerability]:
        return [v for v in self.open_vulns() if v.patchable]


@dataclass
class Action:
    """A single move chosen by an agent. `params` holds e.g. target/technique."""
    faction: Faction
    type: str                  # value of RedActionType / BlueActionType
    params: Dict[str, str] = field(default_factory=dict)
    rationale: str = ""        # optional free text (LLM agents fill this in)

    def target(self) -> Optional[str]:
        return self.params.get("target")

    def __str__(self) -> str:
        tgt = self.params.get("target", "")
        src = self.params.get("source", "")
        tech = self.params.get("technique", "")
        bits = [self.type]
        if tgt:
            bits.append(f"{src}->{tgt}" if src else tgt)
        if tech:
            bits.append(f"({tech})")
        return " ".join(bits)


@dataclass
class TelemetryEvent:
    """One log line. Red actions may emit these; benign noise is emitted too."""
    step_emitted: int          # when the underlying action happened
    visible_at: int            # when Blue can actually see it (adds latency)
    kind: str                  # EventKind value
    node: str                  # node the event concerns
    technique_id: str = ""     # populated for attack events
    sensor: str = ""           # which Sensor produced it
    is_true_positive: bool = False  # ground truth: did this reflect a real attack?

    def as_blue_view(self) -> Dict[str, str]:
        """What Blue sees — deliberately omits is_true_positive (ground truth)."""
        return {
            "step": str(self.step_emitted),
            "kind": self.kind,
            "node": self.node,
            "technique_id": self.technique_id,
            "sensor": self.sensor,
        }
