"""Load and save networks as JSON, so a real architecture can be described in a
file instead of hand-coded Python. Zero-dependency (stdlib json).

Schema (all fields optional unless noted):

    {
      "config":   { "max_steps": 40, "analyst_budget": 50, "telemetry_latency": [1, 3], ... },
      "firewall": { "internet": ["dmz"], "dmz": ["dmz", "internal"], ... },
      "nodes": [
        { "name": "web_proxy",           # required, unique
          "segment": "dmz",              # zone; firewall policy is between zones
          "entry": true,                 # internet-facing foothold
          "crown_jewel": false,          # holds the data Red wants
          "value": 1,
          "services": ["https"],
          "connections": ["app_server"], # symmetry is auto-completed
          "sensors": { "NETWORK": 0.8, "ENDPOINT": 0.6 },   # coverage 0..1 (0 = blind spot)
          "vulnerabilities": [
            { "technique": "T1190", "name": "Exploit Public-Facing App",
              "cve": "CVE-SIM-1", "success": 0.7, "detection": 0.5,
              "service": "https", "grants": "USER",   # USER | ADMIN
              "local": false, "patchable": true }
          ] }
      ]
    }

`load_scenario` returns (nodes, firewall, config_overrides) ready for
`Environment(network=..., firewall=..., config=...)`. `export_scenario` writes a
built-in network back out as a template to edit.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional, Tuple

from .models import AccessLevel, Node, Sensor, Vulnerability

_VALID_SENSORS = {s.value for s in Sensor}


def _vuln_from(d: dict) -> Vulnerability:
    grants = d.get("grants", "USER").upper()
    if grants not in AccessLevel.__members__:
        raise ValueError(f"vulnerability grants must be USER or ADMIN, got {grants!r}")
    return Vulnerability(
        technique_id=d["technique"], name=d.get("name", d["technique"]),
        cve_label=d.get("cve", d["technique"]),
        success_prob=float(d["success"]), detection_prob=float(d["detection"]),
        service=d.get("service", ""), grants=int(AccessLevel[grants]),
        local=bool(d.get("local", False)), patchable=bool(d.get("patchable", True)))


def _node_from(d: dict) -> Node:
    sensors = {}
    for k, v in d.get("sensors", {}).items():
        if k not in _VALID_SENSORS:
            raise ValueError(f"unknown sensor {k!r} on {d['name']!r}; use {_VALID_SENSORS}")
        sensors[k] = float(v)
    return Node(
        name=d["name"], segment=d.get("segment", "internal"),
        services=list(d.get("services", [])), connections=list(d.get("connections", [])),
        value=int(d.get("value", 1)), is_entry=bool(d.get("entry", False)),
        is_crown_jewel=bool(d.get("crown_jewel", False)),
        is_identity=bool(d.get("identity", False)), sensors=sensors,
        vulnerabilities=[_vuln_from(v) for v in d.get("vulnerabilities", [])])


def _validate(nodes: Dict[str, Node]) -> None:
    if not nodes:
        raise ValueError("scenario has no nodes")
    if not any(n.is_entry for n in nodes.values()):
        raise ValueError("scenario needs at least one entry node (\"entry\": true)")
    jewels = [n for n in nodes.values() if n.is_crown_jewel]
    if len(jewels) != 1:
        raise ValueError(f"scenario needs exactly one crown_jewel, found {len(jewels)}")
    for node in nodes.values():
        for c in node.connections:
            if c not in nodes:
                raise ValueError(f"{node.name!r} connects to unknown node {c!r}")


def load_scenario(path: str) -> Tuple[Dict[str, Node], Optional[Dict[str, set]], dict]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    nodes = {n["name"]: _node_from(n) for n in data.get("nodes", [])}
    # Complete edge symmetry so the author need not list both directions.
    for name, node in nodes.items():
        for c in node.connections:
            if c in nodes and name not in nodes[c].connections:
                nodes[c].connections.append(name)
    _validate(nodes)
    firewall = ({k: set(v) for k, v in data["firewall"].items()}
                if "firewall" in data else None)
    config = dict(data.get("config", {}))
    if "telemetry_latency" in config:
        config["telemetry_latency"] = tuple(config["telemetry_latency"])
    return nodes, firewall, config


def scenario_to_dict(nodes: Dict[str, Node], firewall: Optional[Dict[str, set]] = None,
                     config: Optional[dict] = None) -> dict:
    out: dict = {}
    if config:
        out["config"] = config
    if firewall is not None:
        out["firewall"] = {k: sorted(v) for k, v in firewall.items()}
    node_list = []
    for node in nodes.values():
        d = {"name": node.name, "segment": node.segment, "value": node.value,
             "services": node.services, "connections": node.connections,
             "sensors": {k: round(v, 3) for k, v in node.sensors.items()},
             "vulnerabilities": [
                 {"technique": v.technique_id, "name": v.name, "cve": v.cve_label,
                  "success": v.success_prob, "detection": v.detection_prob,
                  "service": v.service, "grants": AccessLevel(v.grants).name,
                  "local": v.local, "patchable": v.patchable}
                 for v in node.vulnerabilities]}
        if node.is_entry:
            d["entry"] = True
        if node.is_crown_jewel:
            d["crown_jewel"] = True
        if node.is_identity:
            d["identity"] = True
        node_list.append(d)
    out["nodes"] = node_list
    return out


def export_scenario(nodes: Dict[str, Node], path: str,
                    firewall: Optional[Dict[str, set]] = None,
                    config: Optional[dict] = None) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(scenario_to_dict(nodes, firewall, config), fh, indent=2)
