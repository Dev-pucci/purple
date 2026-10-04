"""Scenarios: the hand-built default network plus a seeded random generator.

Default topology (edges are bidirectional reachability):

    internet
       |
   [web_dmz]  --- [app_server] --- [db_cluster]*   (* crown jewel)
                        |
                   [workstation]

Red starts with a foothold path through web_dmz (the entry node). The goal is
to reach db_cluster and exfiltrate. Blue must detect and evict without taking
the whole network down.

`random_network(seed)` builds a different enterprise-shaped network per seed:
1-2 internet-facing entry nodes, 3-6 internal hosts with extra cross-links (so
there is usually more than one route), and the crown jewel behind 1-2 internal
hosts. Every entry node also has an unpatchable credential route (T1078), so
Blue can slow Red's initial access with patching but never fully close it.
"""
from __future__ import annotations

import random
from typing import Dict, List, Optional

from .models import Node, Vulnerability


def _stolen_credentials(label: str) -> Vulnerability:
    """Phished/reused credentials: always usable, no patch fixes them."""
    return Vulnerability(technique_id="T1078", name="Valid Accounts", cve_label=label,
                         success_prob=0.25, detection_prob=0.3, patchable=False)


def default_network() -> Dict[str, Node]:
    return {
        "web_dmz": Node(
            name="web_dmz",
            services=["http", "https"],
            is_entry=True,
            value=1,
            connections=["app_server"],
            vulnerabilities=[
                Vulnerability(
                    technique_id="T1190",
                    name="Exploit Public-Facing Application",
                    cve_label="CVE-SIM-0001",
                    success_prob=0.75,
                    detection_prob=0.45,
                ),
                _stolen_credentials("CRED-SIM-0001"),
            ],
        ),
        "app_server": Node(
            name="app_server",
            services=["http", "rpc"],
            value=2,
            connections=["web_dmz", "db_cluster", "workstation"],
            vulnerabilities=[
                Vulnerability(
                    technique_id="T1210",
                    name="Exploitation of Remote Services",
                    cve_label="CVE-SIM-0002",
                    success_prob=0.6,
                    detection_prob=0.5,
                ),
            ],
        ),
        "workstation": Node(
            name="workstation",
            services=["smb"],
            value=1,
            connections=["app_server"],
            vulnerabilities=[
                Vulnerability(
                    technique_id="T1078",
                    name="Valid Accounts",
                    cve_label="CVE-SIM-0003",
                    success_prob=0.55,
                    detection_prob=0.35,
                ),
            ],
        ),
        "db_cluster": Node(
            name="db_cluster",
            services=["postgresql"],
            value=5,
            is_crown_jewel=True,
            connections=["app_server"],
            vulnerabilities=[
                Vulnerability(
                    technique_id="T1210",
                    name="Exploitation of Remote Services",
                    cve_label="CVE-SIM-0004",
                    success_prob=0.5,
                    detection_prob=0.7,
                ),
            ],
        ),
    }


# --------------------------------------------------------------- random networks
_ENTRY_ROLES = {"web_dmz": ["http", "https"], "vpn_gateway": ["vpn"]}
_INTERNAL_ROLES = {
    "app_server": ["http", "rpc"], "file_server": ["smb"], "mail_server": ["smtp", "imap"],
    "jump_host": ["ssh", "rdp"], "ci_runner": ["ssh", "http"], "dev_workstation": ["smb", "rdp"],
    "hr_workstation": ["smb"], "print_server": ["ipp"], "domain_controller": ["ldap", "kerberos"],
    "backup_server": ["ssh", "rsync"],
}
_INTERNAL_VULNS = [
    # technique, name, success range, detection range
    ("T1210", "Exploitation of Remote Services", (0.5, 0.7), (0.4, 0.6)),
    ("T1078", "Valid Accounts", (0.45, 0.6), (0.3, 0.45)),
]


def random_network(seed: int, internal: Optional[int] = None) -> Dict[str, Node]:
    """A seeded, enterprise-shaped network. Same seed -> same network."""
    rng = random.Random(f"{seed}:network")
    u = lambda lo_hi: round(rng.uniform(*lo_hi), 2)  # noqa: E731
    n_internal = internal if internal is not None else rng.randint(3, 6)
    entries = list(_ENTRY_ROLES)[:rng.choice([1, 1, 2])]
    roles = rng.sample(sorted(_INTERNAL_ROLES), n_internal)
    jewel = "db_cluster"

    edges = set()

    def link(a: str, b: str) -> None:
        edges.add(tuple(sorted((a, b))))

    # Spanning tree hanging off the entry nodes, then cross-links for extra routes.
    placed: List[str] = list(entries)
    for role in roles:
        link(role, rng.choice(placed))
        placed.append(role)
    for entry in entries:  # every entry node must lead somewhere
        if not any(entry in e for e in edges):
            link(entry, rng.choice(roles))
    for i, a in enumerate(roles):
        for b in roles[i + 1:]:
            if rng.random() < 0.25:
                link(a, b)
    # The crown jewel sits behind 1-2 internal hosts, never directly on the DMZ.
    for role in rng.sample(roles, min(len(roles), rng.choice([1, 2, 2]))):
        link(jewel, role)

    counter = iter(range(1, 1000))
    label = lambda: f"CVE-SIM-R{next(counter):03d}"  # noqa: E731
    nodes: Dict[str, Node] = {}
    for name in entries:
        nodes[name] = Node(name=name, services=_ENTRY_ROLES[name], is_entry=True, value=1,
                           vulnerabilities=[
                               Vulnerability("T1190", "Exploit Public-Facing Application",
                                             label(), u((0.6, 0.8)), u((0.35, 0.55))),
                               _stolen_credentials(f"CRED-SIM-{name}"),
                           ])
    for name in roles:
        tech, vname, succ, det = rng.choice(_INTERNAL_VULNS)
        nodes[name] = Node(name=name, services=_INTERNAL_ROLES[name], value=rng.randint(1, 3),
                           vulnerabilities=[Vulnerability(tech, vname, label(), u(succ), u(det))])
    nodes[jewel] = Node(name=jewel, services=["postgresql"], value=5, is_crown_jewel=True,
                        vulnerabilities=[Vulnerability("T1210", "Exploitation of Remote Services",
                                                       label(), u((0.45, 0.6)), u((0.6, 0.8)))])
    for a, b in sorted(edges):
        nodes[a].connections.append(b)
        nodes[b].connections.append(a)
    return nodes


SCENARIOS = ("default", "random")


def make_network(scenario: str, seed: int) -> Dict[str, Node]:
    if scenario == "default":
        return default_network()
    if scenario == "random":
        return random_network(seed)
    raise ValueError(f"Unknown scenario {scenario!r} (use one of {', '.join(SCENARIOS)})")


DEFAULT_CONFIG = {
    "scenario": "default",         # "default" (hand-built) or "random" (seeded generator)
    "max_steps": 30,
    "seed": 7,
    "telemetry_latency": (1, 3),   # min..max steps before Blue sees an event
    "noise_per_step": 1,           # benign noise events per step (false positives)
    "lookalike_prob": 0.3,         # share of noise that looks like an attack event
    "investigate_boost": 0.35,     # detection_prob added to a node when investigated
    "restore_duration": 2,         # Red turns a node stays offline while re-imaging
    "patch_duration": 1,           # Red turns a node stays offline while patching
    "lateral_success": 0.35,       # chance a credentialed LATERAL_MOVE takes over a neighbour
    "lateral_detection": 0.4,      # base chance a LATERAL_MOVE shows up in telemetry
    "exfil_steps": 3,              # EXFILTRATE turns needed to steal the crown jewel
    "exfil_detection": 0.8,        # base chance each EXFILTRATE turn is logged
}
