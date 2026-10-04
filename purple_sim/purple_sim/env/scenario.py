"""Default scenario: a small, realistic-ish enterprise network.

Topology (edges are bidirectional reachability):

    internet
       |
   [web_dmz]  --- [app_server] --- [db_cluster]*   (* crown jewel)
                        |
                   [workstation]

Red starts with a foothold path through web_dmz (the entry node). The goal is
to reach db_cluster and exfiltrate. Blue must detect and evict without taking
the whole network down.
"""
from __future__ import annotations

from typing import Dict

from .models import Node, Vulnerability


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


DEFAULT_CONFIG = {
    "max_steps": 30,
    "seed": 7,
    "telemetry_latency": (1, 3),   # min..max steps before Blue sees an event
    "noise_per_step": 1,           # benign noise events per step (false positives)
    "investigate_boost": 0.35,     # detection_prob added to a node when investigated
    "restore_duration": 2,         # Red turns a node stays offline while re-imaging
    "lateral_success": 0.35,       # chance a credentialed LATERAL_MOVE takes over a neighbour
    "lateral_detection": 0.4,      # base chance a LATERAL_MOVE shows up in telemetry
}
