"""Scenarios: the hand-built default network plus a seeded random generator.

Default topology (edges are bidirectional reachability; segments in brackets):

    internet
       |
   [web_dmz:dmz] --- [app_server:internal] --- [db_cluster:secure]*  (* crown jewel)
                            |
                     [workstation:internal]

Red starts internet-facing at web_dmz. To steal the data it must gain a
foothold (EXPLOIT a known remote vuln after a SCAN), pivot inward
(LATERAL_MOVE), cross the firewall into the `secure` segment (which needs ADMIN,
so it must ESCALATE), and finally hold the crown jewel at ADMIN to EXFILTRATE.

A firewall allows traffic only between the segment pairs in `FIREWALL`.
Each host carries sensors (NETWORK / ENDPOINT) with a coverage level; a low or
zero coverage is a detection blind spot. Entry nodes also carry an unpatchable
stolen-credentials vuln (T1078), so Blue can slow initial access but never
fully close it.

`random_network(seed)` builds a different enterprise-shaped network per seed.
"""
from __future__ import annotations

import random
from typing import Dict, List, Optional, Tuple

from .models import AccessLevel, Node, Sensor, Vulnerability

# Directed firewall policy: src_segment -> segments reachable from it. Crossing
# into a segment in ADMIN_SEGMENTS additionally requires ADMIN on the source.
FIREWALL: Dict[str, set] = {
    "internet": {"dmz"},
    "dmz": {"dmz", "internal"},
    "internal": {"internal", "dmz", "secure"},
    "secure": {"secure", "internal"},
}
ADMIN_SEGMENTS = ("secure",)


def _stolen_credentials(label: str) -> Vulnerability:
    """Phished/reused credentials: always usable, no patch fixes them."""
    return Vulnerability("T1078", "Valid Accounts", label, success_prob=0.3,
                         detection_prob=0.3, service="auth", grants=AccessLevel.USER,
                         patchable=False)


def _privesc(label: str, success: float = 0.8, detection: float = 0.5) -> Vulnerability:
    """A local privilege-escalation weakness: USER -> ADMIN via ESCALATE."""
    return Vulnerability("T1068", "Exploitation for Privilege Escalation", label,
                         success_prob=success, detection_prob=detection,
                         service="os", grants=AccessLevel.ADMIN, local=True)


def default_network() -> Dict[str, Node]:
    return {
        "web_dmz": Node(
            name="web_dmz", segment="dmz", is_entry=True, value=1,
            services=["http", "https"], connections=["app_server"],
            sensors={Sensor.NETWORK: 0.8, Sensor.ENDPOINT: 0.6},
            vulnerabilities=[
                Vulnerability("T1190", "Exploit Public-Facing Application", "CVE-SIM-0001",
                              success_prob=0.75, detection_prob=0.45, service="http",
                              grants=AccessLevel.USER),
                _stolen_credentials("CRED-SIM-0001"),
                _privesc("CVE-SIM-0001P"),
            ],
        ),
        "app_server": Node(
            name="app_server", segment="internal", value=2,
            services=["http", "rpc"], connections=["web_dmz", "db_cluster", "workstation"],
            sensors={Sensor.NETWORK: 0.7, Sensor.ENDPOINT: 0.7},
            vulnerabilities=[
                Vulnerability("T1210", "Exploitation of Remote Services", "CVE-SIM-0002",
                              success_prob=0.6, detection_prob=0.5, service="rpc",
                              grants=AccessLevel.USER),
                _privesc("CVE-SIM-0002P"),
            ],
        ),
        "workstation": Node(
            name="workstation", segment="internal", value=1,
            services=["smb"], connections=["app_server"],
            sensors={Sensor.NETWORK: 0.6, Sensor.ENDPOINT: 0.0},  # EDR blind spot
            vulnerabilities=[
                Vulnerability("T1078", "Valid Accounts", "CVE-SIM-0003",
                              success_prob=0.55, detection_prob=0.35, service="smb",
                              grants=AccessLevel.USER),
                _privesc("CVE-SIM-0003P"),
            ],
        ),
        "db_cluster": Node(
            name="db_cluster", segment="secure", is_crown_jewel=True, value=5,
            services=["postgresql"], connections=["app_server"],
            sensors={Sensor.NETWORK: 0.8, Sensor.ENDPOINT: 0.9},
            vulnerabilities=[
                Vulnerability("T1210", "Exploitation of Remote Services", "CVE-SIM-0004",
                              success_prob=0.5, detection_prob=0.7, service="postgresql",
                              grants=AccessLevel.USER),
                _privesc("CVE-SIM-0004P"),
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
_REMOTE_VULNS = [
    ("T1210", "Exploitation of Remote Services", (0.5, 0.7), (0.4, 0.6)),
    ("T1190", "Exploit Public-Facing Application", (0.55, 0.75), (0.4, 0.6)),
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

    placed: List[str] = list(entries)
    for role in roles:
        link(role, rng.choice(placed))
        placed.append(role)
    for entry in entries:
        if not any(entry in e for e in edges):
            link(entry, rng.choice(roles))
    for i, a in enumerate(roles):
        for b in roles[i + 1:]:
            if rng.random() < 0.25:
                link(a, b)
    for role in rng.sample(roles, min(len(roles), rng.choice([1, 2, 2]))):
        link(jewel, role)

    counter = iter(range(1, 1000))
    label = lambda: f"CVE-SIM-R{next(counter):03d}"  # noqa: E731

    def sensors() -> Dict[str, float]:
        # Occasionally a sensor is absent (coverage 0) — a blind spot.
        net = rng.choice([0.0, 0.5, 0.6, 0.7, 0.8])
        edr = rng.choice([0.0, 0.0, 0.4, 0.6, 0.8])
        return {Sensor.NETWORK: net, Sensor.ENDPOINT: edr}

    nodes: Dict[str, Node] = {}
    for name in entries:
        svc = _ENTRY_ROLES[name]
        nodes[name] = Node(name=name, segment="dmz", is_entry=True, value=1, services=svc,
                           sensors=sensors(), vulnerabilities=[
                               Vulnerability("T1190", "Exploit Public-Facing Application",
                                             label(), u((0.6, 0.8)), u((0.35, 0.55)),
                                             service=svc[0], grants=AccessLevel.USER),
                               _stolen_credentials(f"CRED-SIM-{name}"),
                               _privesc(label()),
                           ])
    for name in roles:
        tech, vname, succ, det = rng.choice(_REMOTE_VULNS)
        svc = _INTERNAL_ROLES[name]
        nodes[name] = Node(name=name, segment="internal", value=rng.randint(1, 3), services=svc,
                           sensors=sensors(), vulnerabilities=[
                               Vulnerability(tech, vname, label(), u(succ), u(det),
                                             service=svc[0], grants=AccessLevel.USER),
                               _privesc(label()),
                           ])
    nodes[jewel] = Node(name=jewel, segment="secure", is_crown_jewel=True, value=5,
                        services=["postgresql"],
                        sensors={Sensor.NETWORK: u((0.7, 0.9)), Sensor.ENDPOINT: u((0.7, 0.9))},
                        vulnerabilities=[
                            Vulnerability("T1210", "Exploitation of Remote Services", label(),
                                          u((0.45, 0.6)), u((0.6, 0.8)), service="postgresql",
                                          grants=AccessLevel.USER),
                            _privesc(label()),
                        ])
    for a, b in sorted(edges):
        nodes[a].connections.append(b)
        nodes[b].connections.append(a)
    return nodes


# ----------------------------------------------- representative enterprise network
def _remote(technique: str, name: str, label: str, success: float, detection: float,
           service: str) -> Vulnerability:
    return Vulnerability(technique, name, label, success, detection, service=service,
                         grants=AccessLevel.USER)


def enterprise_network() -> Dict[str, Node]:
    """A hand-built, multi-tier enterprise to model a real site against.

    Edit this to match your environment (segments, host roles, which hosts have
    EDR, where the data sits). It reuses the FIREWALL policy below. Shape:

        internet
          |                               [internal]
      [dmz] web_proxy --- app_server --- domain_controller --- workstation_eng
            vpn_gateway -- jump_host  \\-- file_server --------- workstation_hr
                              |            |
                              +-- app_server --- db_cluster*  [secure] (* crown jewel)
    """
    def host(name, segment, services, conns, net, edr, value=1, remote=None,
             entry=False, jewel=False, identity=False):
        vulns = []
        if remote is not None:
            vulns.append(remote)
        if entry:
            vulns.append(_stolen_credentials(f"CRED-{name}"))
        vulns.append(_privesc(f"PRIV-{name}"))
        return Node(name=name, segment=segment, services=services, connections=conns,
                    value=value, is_entry=entry, is_crown_jewel=jewel, is_identity=identity,
                    sensors={Sensor.NETWORK: net, Sensor.ENDPOINT: edr},
                    vulnerabilities=vulns)

    nodes = [
        host("web_proxy", "dmz", ["https"], ["app_server"], 0.8, 0.6, value=1, entry=True,
             remote=_remote("T1190", "Exploit Public-Facing Application", "CVE-ENT-01",
                            0.7, 0.5, "https")),
        host("vpn_gateway", "dmz", ["vpn"], ["jump_host"], 0.7, 0.5, value=1, entry=True,
             remote=_remote("T1190", "Exploit Public-Facing Application", "CVE-ENT-02",
                            0.6, 0.5, "vpn")),
        host("app_server", "internal", ["http", "rpc"],
             ["web_proxy", "jump_host", "domain_controller", "db_cluster"], 0.7, 0.7, value=2,
             remote=_remote("T1210", "Exploitation of Remote Services", "CVE-ENT-03",
                            0.6, 0.5, "rpc")),
        host("jump_host", "internal", ["ssh", "rdp"], ["vpn_gateway", "app_server", "file_server"],
             0.7, 0.6, value=2,
             remote=_remote("T1021", "Remote Services", "CVE-ENT-04", 0.55, 0.5, "rdp")),
        host("domain_controller", "internal", ["ldap", "kerberos"],
             ["app_server", "file_server", "workstation_eng", "workstation_hr"], 0.8, 0.9, value=4,
             identity=True,  # tier-0: ADMIN here grants domain-wide lateral movement
             remote=_remote("T1210", "Exploitation of Remote Services", "CVE-ENT-05",
                            0.5, 0.6, "ldap")),
        host("file_server", "internal", ["smb"],
             ["jump_host", "domain_controller", "workstation_eng", "workstation_hr"], 0.6, 0.4,
             value=2, remote=_remote("T1210", "Exploitation of Remote Services", "CVE-ENT-06",
                                     0.6, 0.45, "smb")),
        host("workstation_eng", "internal", ["smb", "rdp"],
             ["domain_controller", "file_server"], 0.5, 0.0, value=1,
             remote=_remote("T1078", "Valid Accounts", "CVE-ENT-07", 0.55, 0.35, "rdp")),
        host("workstation_hr", "internal", ["smb"], ["domain_controller", "file_server"],
             0.5, 0.0, value=1,
             remote=_remote("T1078", "Valid Accounts", "CVE-ENT-08", 0.55, 0.35, "smb")),
        host("db_cluster", "secure", ["postgresql"], ["app_server"], 0.8, 0.9, value=5, jewel=True,
             remote=_remote("T1210", "Exploitation of Remote Services", "CVE-ENT-09",
                            0.5, 0.7, "postgresql")),
    ]
    return {n.name: n for n in nodes}


def flat_network() -> Dict[str, Node]:
    """A small-business 'pancake': one DMZ host, everything else on one flat
    internal LAN with the database sitting right among the workstations, and
    sparse endpoint monitoring. A deliberately weaker posture than `enterprise`
    — no secure segment to cross, so compare the two to see what segmentation
    and sensor coverage buy you.
    """
    def host(name, services, conns, net, edr, value=1, remote=None, entry=False,
             jewel=False, segment="internal"):
        vulns = [remote] if remote is not None else []
        if entry:
            vulns.append(_stolen_credentials(f"CRED-{name}"))
        vulns.append(_privesc(f"PRIV-{name}"))
        return Node(name=name, segment=segment, services=services, connections=conns,
                    value=value, is_entry=entry, is_crown_jewel=jewel,
                    sensors={Sensor.NETWORK: net, Sensor.ENDPOINT: edr}, vulnerabilities=vulns)

    nodes = [
        host("router", ["https"], ["lan_switch"], 0.6, 0.3, value=1, entry=True, segment="dmz",
             remote=_remote("T1190", "Exploit Public-Facing Application", "CVE-FLAT-01",
                            0.7, 0.4, "https")),
        host("lan_switch", ["snmp"], ["router", "pc_1", "pc_2", "accounts_pc", "nas", "db"],
             0.5, 0.0, value=1,
             remote=_remote("T1210", "Exploitation of Remote Services", "CVE-FLAT-02",
                            0.6, 0.4, "snmp")),
        host("pc_1", ["smb"], ["lan_switch"], 0.4, 0.0, value=1,
             remote=_remote("T1078", "Valid Accounts", "CVE-FLAT-03", 0.6, 0.3, "smb")),
        host("pc_2", ["smb"], ["lan_switch"], 0.4, 0.0, value=1,
             remote=_remote("T1078", "Valid Accounts", "CVE-FLAT-04", 0.6, 0.3, "smb")),
        host("accounts_pc", ["smb", "rdp"], ["lan_switch"], 0.4, 0.2, value=3,
             remote=_remote("T1078", "Valid Accounts", "CVE-FLAT-05", 0.6, 0.3, "rdp")),
        host("nas", ["smb", "nfs"], ["lan_switch"], 0.5, 0.0, value=3,
             remote=_remote("T1210", "Exploitation of Remote Services", "CVE-FLAT-06",
                            0.6, 0.4, "smb")),
        host("db", ["mysql"], ["lan_switch"], 0.5, 0.4, value=5, jewel=True,
             remote=_remote("T1210", "Exploitation of Remote Services", "CVE-FLAT-07",
                            0.55, 0.5, "mysql")),
    ]
    return {n.name: n for n in nodes}


# ------------------------------------------------------- web-application scenario
# Firewall for the web stack's trust layers (distinct from the network FIREWALL).
WEBAPP_FIREWALL: Dict[str, set] = {
    "internet": {"web"},
    "web": {"web", "app"},
    "app": {"app", "secure"},
    "secure": {"secure", "app"},
}


def webapp_network() -> Dict[str, Node]:
    """An abstract web application's attack surface by trust layer. This is an
    *approximation* of web-app security inside a graph engine: the layers and
    OWASP-flavoured weaknesses are real concepts, but there are no real requests
    or payloads. Shape:

        internet -> [web_app : web]  (WAF-watched, A03 injection / web shell)
                        |
                    [api_service : app]  (A01 broken access control, A10 SSRF)
                        |   \\
        [auth_service : app, identity]   [user_db : secure]* (* crown jewel data)

    The WAF gives web_app strong NETWORK detection; the data store is in a
    `secure` segment, so reaching it needs ADMIN (a stolen session/token) on the
    pivot — the web analogue of "own the app, then forge your way to the data".
    """
    def vuln(tech, name, cve, succ, det, service, grants=AccessLevel.USER, local=False):
        return Vulnerability(tech, name, cve, succ, det, service=service,
                             grants=grants, local=local)

    return {
        "web_app": Node(
            name="web_app", segment="web", is_entry=True, value=1,
            services=["https"], connections=["api_service"],
            sensors={Sensor.NETWORK: 0.85, Sensor.ENDPOINT: 0.5},  # WAF + app logs
            vulnerabilities=[
                vuln("T1190", "A03 Injection (SQLi/RCE)", "WEB-A03", 0.6, 0.6, "https"),
                vuln("T1505.003", "A08 Web Shell upload", "WEB-A08", 0.4, 0.5, "https",
                     local=True, grants=AccessLevel.ADMIN),
            ]),
        "api_service": Node(
            name="api_service", segment="app", value=2,
            services=["http-api"], connections=["web_app", "auth_service", "user_db"],
            sensors={Sensor.NETWORK: 0.5, Sensor.ENDPOINT: 0.6},
            vulnerabilities=[
                vuln("T1078", "A01 Broken Access Control", "WEB-A01", 0.6, 0.45, "http-api"),
                vuln("T1090", "A10 SSRF pivot", "WEB-A10", 0.5, 0.4, "http-api",
                     local=True, grants=AccessLevel.ADMIN),
            ]),
        "auth_service": Node(
            name="auth_service", segment="app", is_identity=True, value=4,
            services=["oauth"], connections=["api_service", "user_db"],
            sensors={Sensor.NETWORK: 0.6, Sensor.ENDPOINT: 0.7},
            vulnerabilities=[
                vuln("T1078", "A07 Auth failure (token/session theft)", "WEB-A07",
                     0.5, 0.5, "oauth"),
                _privesc("WEB-A07P"),
            ]),
        "user_db": Node(
            name="user_db", segment="secure", is_crown_jewel=True, value=5,
            services=["postgresql"], connections=["api_service", "auth_service"],
            sensors={Sensor.NETWORK: 0.7, Sensor.ENDPOINT: 0.85},
            vulnerabilities=[
                vuln("T1213", "A01 Direct object access to records", "WEB-DB", 0.5, 0.7,
                     "postgresql"),
                _privesc("WEB-DBP"),
            ]),
    }


SCENARIOS = ("default", "random", "enterprise", "flat", "webapp")
_BUILDERS = {"default": default_network, "enterprise": enterprise_network,
             "flat": flat_network, "webapp": webapp_network}
_FIREWALLS = {"webapp": WEBAPP_FIREWALL}  # others fall back to the network FIREWALL


def make_network(scenario: str, seed: int) -> Dict[str, Node]:
    if scenario == "random":
        return random_network(seed)
    if scenario in _BUILDERS:
        return _BUILDERS[scenario]()
    raise ValueError(f"Unknown scenario {scenario!r} (use one of {', '.join(SCENARIOS)})")


def scenario_firewall(scenario: str) -> Dict[str, set]:
    """The firewall policy a built-in scenario uses (web layers differ from LAN zones)."""
    return _FIREWALLS.get(scenario, FIREWALL)


DEFAULT_CONFIG = {
    "scenario": "default",         # "default" (hand-built) or "random" (seeded generator)
    "max_steps": 40,
    "seed": 7,
    "telemetry_latency": (1, 3),   # min..max steps before Blue sees an event
    "noise_per_step": 1,           # benign noise events per step (false positives)
    "lookalike_prob": 0.3,         # share of noise that looks like an attack event
    "log_retention": 12,           # steps an event stays in Blue's working view (0 = forever)
    "investigate_boost": 0.35,     # detection_prob added to a node when investigated
    "restore_duration": 2,         # Red turns a node stays offline while re-imaging
    "patch_duration": 1,           # Red turns a node stays offline while patching
    "escalate_detection": 0.5,     # base chance an ESCALATE is logged
    "escalate_fallback_success": 0.2,  # harder token-theft privesc when the vuln is patched
    "lateral_success": 0.5,        # chance a LATERAL_MOVE foothold takes
    "lateral_detection": 0.4,      # base chance a LATERAL_MOVE shows up in telemetry
    "exfil_steps": 3,              # EXFILTRATE turns needed to steal the crown jewel
    "exfil_detection": 0.8,        # base chance each EXFILTRATE turn is logged
    "stealth_success_mult": 0.55,  # mode="stealth": multiplies an action's success odds
    "stealth_detection_mult": 0.3, # mode="stealth": multiplies its detection odds (quieter)
    "alert_fatigue": 0.0,          # 0 = off; up to this fraction of detection is lost when swamped
    "fatigue_capacity": 15,        # visible-alert volume at which fatigue saturates
    "analyst_budget": 50,          # total action-points Blue may spend across a game (0 = unlimited)
    "analyst_costs": {"INVESTIGATE": 1, "PATCH": 2, "ISOLATE": 2, "RESTORE": 3,
                      "DECOY": 1, "ROTATE_CREDS": 2},
}
