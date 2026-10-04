"""Smoke tests — run with: python -m pytest, or just python tests/test_environment.py"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from purple_sim.agents import HeuristicBlue, make_blue, make_red
from purple_sim.agents.rl_interface import PurpleRedEnv, RandomRLAgent
from purple_sim.env.environment import Environment
from purple_sim.env.models import Action, BlueActionType, Faction, RedActionType
from purple_sim.orchestrator import Orchestrator, SimConfig
from purple_sim.scoring.scorer import Scorer

MONITOR = Action(Faction.BLUE, BlueActionType.MONITOR.value, {})
WAIT = Action(Faction.RED, RedActionType.WAIT.value, {})


def red(kind, **params):
    return Action(Faction.RED, kind, params)


def blue(kind, target):
    return Action(Faction.BLUE, kind, {"target": target})


def give_foothold(env, name):
    env.red.discovered.add(name)
    env.red.footholds.add(name)
    env.nodes[name].compromised = True


def make_certain(env, name):
    """Exploits of `name` always land and are always logged."""
    for v in env.nodes[name].vulnerabilities:
        v.success_prob = 1.0
        v.detection_prob = 1.0


def test_game_terminates():
    env = Environment(config={"seed": 1, "max_steps": 30})
    report = Orchestrator(env, make_red("heuristic"), make_blue("heuristic"),
                          SimConfig(verbose=False, show_report=False)).run()
    assert env.done
    assert report["winner"] in ("RED", "BLUE")
    assert report["steps"] <= 30


def test_blue_never_sees_ground_truth():
    # Play a full game first so the telemetry feed is actually populated.
    env = Environment(config={"seed": 2})
    Orchestrator(env, make_red("heuristic"), make_blue("heuristic"),
                 SimConfig(verbose=False, show_report=False)).run()
    view = env.blue_view()
    assert view["telemetry"], "expected telemetry after a full game"
    # Blue's node view must not leak the `compromised` flag.
    for node_info in view["nodes"].values():
        assert "compromised" not in node_info
    # Telemetry entries must not expose the true-positive label.
    for event in view["telemetry"]:
        assert "is_true_positive" not in event


def test_exploit_requires_discovery():
    env = Environment(config={"seed": 3})
    # db_cluster is not discovered at start; exploiting it should fail cleanly.
    action = Action(Faction.RED, RedActionType.EXPLOIT.value, {"target": "db_cluster"})
    noop = Action(Faction.BLUE, BlueActionType.MONITOR.value, {})
    result = env.step(action, noop)
    assert "not discovered" in result.red_outcome


def test_coverage_is_bounded():
    env = Environment(config={"seed": 4})
    report = Orchestrator(env, make_red("heuristic"), make_blue("heuristic"),
                          SimConfig(verbose=False, show_report=False)).run()
    assert 0.0 <= report["coverage_pct"] <= 100.0


def test_rl_env_runs():
    env = PurpleRedEnv(seed=5)
    obs = env.reset()
    assert len(obs) == env.obs_dim
    agent = RandomRLAgent(env, seed=5)
    done = False
    steps = 0
    while not done and steps < 100:
        obs, reward, done, info = env.step(agent.act(obs))
        steps += 1
    assert done


def test_mock_llm_runs_offline():
    # No API key needed: mock mode must fall back to the heuristic brain.
    env = Environment(config={"seed": 6})
    report = Orchestrator(env, make_red("llm", mock=True), make_blue("llm", mock=True),
                          SimConfig(verbose=False, show_report=False)).run()
    assert report["winner"] in ("RED", "BLUE")


def test_red_needs_a_route_not_just_discovery():
    env = Environment(config={"seed": 10})
    env.red.discovered.update({"app_server", "db_cluster"})
    r = env.step(red("SCAN", target="db_cluster"), MONITOR)
    assert "no route" in r.red_outcome and not r.red_executed
    r = env.step(red("EXPLOIT", target="app_server"), MONITOR)
    assert "no route" in r.red_outcome and not r.red_executed
    # A foothold on the neighbouring web_dmz opens the route.
    give_foothold(env, "web_dmz")
    r = env.step(red("EXPLOIT", target="app_server"), MONITOR)
    assert r.red_executed and "no route" not in r.red_outcome


def test_isolated_foothold_cannot_pivot_or_exfiltrate():
    env = Environment(config={"seed": 11})
    give_foothold(env, "app_server")
    give_foothold(env, "db_cluster")
    env.nodes["db_cluster"].isolated = True
    r = env.step(red("EXFILTRATE", target="db_cluster"), MONITOR)
    assert "blocked" in r.red_outcome and not env.red_exfiltrated
    env.nodes["app_server"].isolated = True
    r = env.step(red("LATERAL_MOVE", source="app_server", target="workstation"), MONITOR)
    assert "isolated" in r.red_outcome and not r.red_executed


def test_restore_takes_node_offline_then_returns_it_clean():
    env = Environment(config={"seed": 12, "restore_duration": 2})
    give_foothold(env, "web_dmz")
    env.nodes["web_dmz"].isolated = True
    env.step(WAIT, blue("RESTORE", "web_dmz"))
    assert "web_dmz" not in env.red.footholds
    for _ in range(2):  # offline for exactly restore_duration Red turns
        r = env.step(red("EXPLOIT", target="web_dmz"), MONITOR)
        assert "offline" in r.red_outcome
    node = env.nodes["web_dmz"]
    assert node.restoring == 0 and not node.isolated
    r = env.step(red("EXPLOIT", target="web_dmz"), MONITOR)
    assert "offline" not in r.red_outcome


def test_repeated_restores_of_a_clean_node_are_false_positives():
    env = Environment(config={"seed": 13, "max_steps": 20})
    make_certain(env, "web_dmz")
    env.step(red("EXPLOIT", target="web_dmz"), MONITOR)
    while not env.done:
        env.step(WAIT, blue("RESTORE", "web_dmz"))
    report = Scorer().final_report(env)
    assert report["true_positives"] == 1     # only the first restore evicted anyone
    assert report["false_positives"] >= 5
    assert report["blue_score"] < 0


def test_blue_decides_on_telemetry_released_this_step():
    env = Environment(config={"seed": 14, "telemetry_latency": (1, 1), "noise_per_step": 0})
    make_certain(env, "web_dmz")
    env.step(red("EXPLOIT", target="web_dmz"), MONITOR)
    seen = []

    def policy(view):
        seen.extend(view["telemetry"])
        return MONITOR

    env.step(WAIT, policy)
    assert any(e["kind"] == "EXPLOIT_ATTEMPT" and e["step"] == "1" for e in seen)


def test_coverage_counts_only_responses_after_the_event_is_visible():
    cfg = {"seed": 15, "telemetry_latency": (2, 2), "noise_per_step": 0}

    # Blue acts before it could have seen anything -> not a detection.
    env = Environment(config=cfg)
    make_certain(env, "web_dmz")
    env.step(red("EXPLOIT", target="web_dmz"), blue("ISOLATE", "web_dmz"))
    env.step(WAIT, MONITOR)
    env.step(WAIT, MONITOR)  # event becomes visible at step 3
    row = Scorer().final_report(env)["coverage_rows"][0]
    assert row["in_telemetry"] and row["seen_at"] == 3 and not row["detected"]

    # INVESTIGATE after it's visible is triage, not a response.
    env = Environment(config=cfg)
    make_certain(env, "web_dmz")
    env.step(red("EXPLOIT", target="web_dmz"), MONITOR)
    env.step(WAIT, MONITOR)
    env.step(WAIT, blue("INVESTIGATE", "web_dmz"))
    assert not Scorer().final_report(env)["coverage_rows"][0]["detected"]

    # RESTORE once it's visible -> detected, with time-to-respond recorded.
    env = Environment(config=cfg)
    make_certain(env, "web_dmz")
    env.step(red("EXPLOIT", target="web_dmz"), MONITOR)
    env.step(WAIT, MONITOR)
    env.step(WAIT, blue("RESTORE", "web_dmz"))
    report = Scorer().final_report(env)
    assert report["coverage_rows"][0]["detected"]
    assert report["mean_time_to_respond"] == 2


def test_report_uses_the_technique_actually_executed():
    env = Environment(config={"seed": 16})
    give_foothold(env, "web_dmz")
    env.red.discovered.add("app_server")
    env.step(red("EXPLOIT", target="app_server"), MONITOR)
    row = Scorer().final_report(env)["coverage_rows"][0]
    expected = env.nodes["app_server"].vulnerabilities[0].technique_id
    assert row["technique"] == expected == "T1210"


def test_heuristic_red_pivots_around_a_patched_crown_jewel():
    env = Environment(config={"seed": 17})
    for v in env.nodes["db_cluster"].vulnerabilities:
        v.patched = True
    agent = make_red("heuristic")
    while not env.done:
        env.step(agent.act(env.red_view()), MONITOR)
    actions = [(h.red_action.type, h.red_action.params.get("target")) for h in env.history]
    assert ("LATERAL_MOVE", "db_cluster") in actions
    assert actions.count(("SCAN", "db_cluster")) == 1  # no rescan loop


def test_heuristic_blue_does_not_refixate_after_restore():
    agent = HeuristicBlue()
    alerts = [{"step": "1", "kind": "LATERAL_DETECTED", "node": "workstation",
               "technique_id": "T1021"}] * 2

    def view(step, isolated=False, restoring=False):
        nodes = {"workstation": {"is_crown_jewel": False, "isolated": isolated,
                                 "restoring": restoring}}
        return {"step": step, "nodes": nodes, "telemetry": alerts}

    assert agent.act(view(2)).type == "ISOLATE"
    assert agent.act(view(3, isolated=True)).type == "RESTORE"
    # Back online after the re-image: the same old alerts must not trigger again.
    later = agent.act(view(6))
    assert later.type not in ("ISOLATE", "RESTORE")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
        passed += 1
    print(f"\n{passed}/{len(tests)} tests passed.")
