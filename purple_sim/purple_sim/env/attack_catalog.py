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
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    # --- web-application flavour (abstract labels; no exploit content) ---------
    "T1505.003": {"name": "Web Shell", "tactic": "Persistence"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access"},
    "T1090": {"name": "Proxy / SSRF pivot", "tactic": "Command and Control"},
    "T1213": {"name": "Data from Information Repositories", "tactic": "Collection"},
}

# OWASP Top 10 (2021) -> the abstract technique this sim uses for it. For
# vocabulary and reporting only; purely a labelling aid, not a detection rule.
OWASP_TO_TECHNIQUE: Dict[str, Dict[str, str]] = {
    "A01 Broken Access Control": {"technique": "T1078"},
    "A03 Injection": {"technique": "T1190"},
    "A07 Identification & Authentication Failures": {"technique": "T1078"},
    "A08 Software & Data Integrity (web shell)": {"technique": "T1505.003"},
    "A10 Server-Side Request Forgery": {"technique": "T1090"},
}


def technique_name(technique_id: str) -> str:
    entry = ATTACK_CATALOG.get(technique_id)
    return entry["name"] if entry else technique_id


def technique_tactic(technique_id: str) -> str:
    entry = ATTACK_CATALOG.get(technique_id)
    return entry["tactic"] if entry else "Unknown"
