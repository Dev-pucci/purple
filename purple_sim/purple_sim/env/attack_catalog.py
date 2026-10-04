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

# OWASP Top 10 (2021) -> the abstract technique this sim labels it with, the red
# move it maps to, and the blue control that answers it. For vocabulary, the
# red/blue guide (WEB.md) and reporting only — a labelling aid, not a detection
# rule, and not exhaustive of any category.
OWASP_TO_TECHNIQUE: Dict[str, Dict[str, str]] = {
    "A01 Broken Access Control": {
        "technique": "T1078", "red": "reach data/functions beyond your role",
        "blue": "enforce authz server-side (PATCH); canary privileged objects (DECOY)"},
    "A02 Cryptographic Failures": {
        "technique": "T1552", "red": "harvest secrets/tokens in weak storage/transit",
        "blue": "rotate secrets (ROTATE_CREDS); enforce TLS/HSTS (webcheck)"},
    "A03 Injection": {
        "technique": "T1190", "red": "inject into a query/command (SQLi/RCE)",
        "blue": "parameterise/patch (PATCH); WAF + app logs (INVESTIGATE)"},
    "A04 Insecure Design": {
        "technique": "T1190", "red": "abuse a missing control the design never had",
        "blue": "add the missing control (PATCH); not fully patch-able"},
    "A05 Security Misconfiguration": {
        "technique": "T1190", "red": "exploit default/verbose/misconfigured surface",
        "blue": "harden config (PATCH); suppress disclosure (webcheck)"},
    "A06 Vulnerable & Outdated Components": {
        "technique": "T1190", "red": "exploit a known component CVE",
        "blue": "patch/upgrade the component (PATCH)"},
    "A07 Identification & Authentication Failures": {
        "technique": "T1078", "red": "bypass/steal auth; forge sessions/tokens",
        "blue": "rotate sessions/keys (ROTATE_CREDS); MFA/lockout (PATCH)"},
    "A08 Software & Data Integrity Failures": {
        "technique": "T1505.003", "red": "plant a web shell / tamper the pipeline",
        "blue": "re-deploy clean (RESTORE); integrity checks (PATCH)"},
    "A09 Security Logging & Monitoring Failures": {
        "technique": "", "red": "operate under a blind spot (no/late telemetry)",
        "blue": "add logging/alerting (INVESTIGATE); shrink latency/retention"},
    "A10 Server-Side Request Forgery": {
        "technique": "T1090", "red": "pivot through the server to internal services",
        "blue": "egress allow-listing / segment (ISOLATE/PATCH)"},
}


def technique_name(technique_id: str) -> str:
    entry = ATTACK_CATALOG.get(technique_id)
    return entry["name"] if entry else technique_id


def technique_tactic(technique_id: str) -> str:
    entry = ATTACK_CATALOG.get(technique_id)
    return entry["tactic"] if entry else "Unknown"
