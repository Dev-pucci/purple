"""MITRE ATT&CK technique catalog (abstract, for vocabulary + scoring).

These are real technique IDs/names used only as labels. No exploit content.
"""
from __future__ import annotations

from typing import Dict

# technique_id -> (name, tactic)
ATTACK_CATALOG: Dict[str, Dict[str, str]] = {
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1210": {"name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
}


def technique_name(technique_id: str) -> str:
    entry = ATTACK_CATALOG.get(technique_id)
    return entry["name"] if entry else technique_id


def technique_tactic(technique_id: str) -> str:
    entry = ATTACK_CATALOG.get(technique_id)
    return entry["tactic"] if entry else "Unknown"
