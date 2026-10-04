"""Core data models for the simulation — plain stdlib dataclasses, no deps."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Faction(str, Enum):
    RED = "RED"
    BLUE = "BLUE"


class RedActionType(str, Enum):
    SCAN = "SCAN"              # discover a node's services/vulns + adjacent nodes
    EXPLOIT = "EXPLOIT"        # attempt to compromise a discovered node
    LATERAL_MOVE = "LATERAL_MOVE"  # pivot from a compromised node to a neighbour
    EXFILTRATE = "EXFILTRATE"  # steal data from a compromised crown-jewel node
    WAIT = "WAIT"             # do nothing (lie low)


class BlueActionType(str, Enum):
    MONITOR = "MONITOR"        # cheap: just observe telemetry this turn
    INVESTIGATE = "INVESTIGATE"  # raise monitoring on a node (better future detection)
    ISOLATE = "ISOLATE"        # cut a node off: blocks exploit/lateral, hurts availability
    PATCH = "PATCH"            # remove a node's vulnerabilities (prevents exploit)
    RESTORE = "RESTORE"        # re-image a node: evicts Red if present, costs availability


# --- telemetry / event kinds Red actions can emit ------------------------------
class EventKind(str, Enum):
    SCAN_DETECTED = "SCAN_DETECTED"
    EXPLOIT_ATTEMPT = "EXPLOIT_ATTEMPT"
    LATERAL_DETECTED = "LATERAL_DETECTED"
    EXFIL_DETECTED = "EXFIL_DETECTED"
    BENIGN_NOISE = "BENIGN_NOISE"


@dataclass
class Vulnerability:
    """An abstract weakness on a node. Not a real exploit — just a labelled flag."""
    technique_id: str          # MITRE ATT&CK id, e.g. "T1190"
    name: str                  # human label, e.g. "Exploit Public-Facing App"
    cve_label: str             # abstract vuln label, e.g. "CVE-SIM-0001"
    success_prob: float        # chance an EXPLOIT attempt lands (0..1)
    detection_prob: float      # base chance the attempt shows up in telemetry (0..1)
    patched: bool = False


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

    # --- ground-truth mutable state (only the Environment sees all of this) ---
    compromised: bool = False
    isolated: bool = False
    monitoring: float = 0.0    # extra detection probability added by Blue
    restoring: int = 0         # steps remaining in a RESTORE operation

    def open_vulns(self) -> List[Vulnerability]:
        return [v for v in self.vulnerabilities if not v.patched]


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
        tech = self.params.get("technique", "")
        bits = [self.type]
        if tgt:
            bits.append(tgt)
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
    is_true_positive: bool = False  # ground truth: did this reflect a real attack?

    def as_blue_view(self) -> Dict[str, str]:
        """What Blue sees — deliberately omits is_true_positive (ground truth)."""
        return {
            "step": str(self.step_emitted),
            "kind": self.kind,
            "node": self.node,
            "technique_id": self.technique_id,
        }
