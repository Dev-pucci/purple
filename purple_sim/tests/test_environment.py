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


def test_some_noise_looks_like_an_attack_but_is_a_false_positive():
    env = Environment(config={"seed": 20, "noise_per_step": 3, "lookalike_prob": 0.5,
                              "max_steps": 20})
    while not env.done:
        env.step(WAIT, MONITOR)
    events = env.bus.visible_events()
    lookalikes = [e for e in events if e.kind != "BENIGN_NOISE"]
    assert lookalikes and not any(e.is_true_positive for e in lookalikes)
    # Exploit look-alikes carry the host's own technique, so kind+technique can't tell.
    for e in lookalikes:
        if e.kind == "EXPLOIT_ATTEMPT":
            assert e.technique_id == env.nodes[e.node].vulnerabilities[0].technique_id


def test_patch_has_a_maintenance_window_and_skips_unpatchable_vulns():
    env = Environment(config={"seed": 21, "patch_duration": 1})
    r = env.step(WAIT, blue("PATCH", "web_dmz"))
    assert r.blue_effective and r.offline_nodes == 1
    r = env.step(red("EXPLOIT", target="web_dmz"), MONITOR)
    assert "offline" in r.red_outcome          # down for the window
    open_vulns = env.nodes["web_dmz"].open_vulns()
    assert [v.technique_id for v in open_vulns] == ["T1078"]  # credentials survive
    r = env.step(WAIT, blue("PATCH", "web_dmz"))
    assert not r.blue_effective                 # nothing patchable left


def test_exfiltration_takes_several_turns_and_restore_wipes_progress():
    env = Environment(config={"seed": 22, "exfil_steps": 3})
    give_foothold(env, "app_server")
    give_foothold(env, "db_cluster")
    exfil = red("EXFILTRATE", target="db_cluster")
    env.step(exfil, MONITOR)
    env.step(exfil, blue("RESTORE", "db_cluster"))  # evicted at 2/3
    assert not env.red_exfiltrated and "db_cluster" not in env.exfil_progress
    env = Environment(config={"seed": 22, "exfil_steps": 3})
    give_foothold(env, "app_server")
    give_foothold(env, "db_cluster")
    for _ in range(3):
        env.step(exfil, MONITOR)
    assert env.red_exfiltrated and env.winner == "RED"


def test_random_networks_are_seeded_and_winnable():
    from purple_sim.env.scenario import random_network
    for seed in range(50):
        net = random_network(seed)
        assert net.keys() == random_network(seed).keys()
        entries = [n for n, node in net.items() if node.is_entry]
        jewel = next(n for n, node in net.items() if node.is_crown_jewel)
        assert entries and not any(jewel in net[e].connections for e in entries)
        for a, node in net.items():  # links are symmetric
            assert all(a in net[b].connections for b in node.connections)
        seen, frontier = set(entries), list(entries)  # jewel reachable from outside
        while frontier:
            for nb in net[frontier.pop()].connections:
                if nb not in seen:
                    seen.add(nb)
                    frontier.append(nb)
        assert jewel in seen
    assert any(len(random_network(s)) != len(random_network(0)) for s in range(1, 20))


def test_same_seed_gives_red_the_same_luck_whatever_blue_does():
    plan = [red("SCAN", target="web_dmz"), red("EXPLOIT", target="web_dmz"),
            red("EXPLOIT", target="web_dmz"), red("EXPLOIT", target="web_dmz")]
    outcomes = []
    for blue_move in (MONITOR, blue("PATCH", "workstation")):
        env = Environment(config={"seed": 23, "noise_per_step": 2})
        outcomes.append([env.step(a, blue_move).red_feedback for a in plan])
    assert outcomes[0] == outcomes[1]


def test_views_show_own_history_without_leaking_the_other_side():
    env = Environment(config={"seed": 24})
    make_certain(env, "web_dmz")
    env.step(red("EXPLOIT", target="web_dmz"), blue("RESTORE", "app_server"))
    red_hist = env.red_view()["recent_actions"]
    assert red_hist and "SUCCESS" in red_hist[0]["result"]
    assert "telemetry" not in red_hist[0]["result"] and "undetected" not in red_hist[0]["result"]
    blue_hist = env.blue_view()["recent_actions"]
    assert blue_hist == [{"step": 1, "action": "RESTORE app_server"}]  # no outcome


def test_downtime_and_stealth_are_scored():
    env = Environment(config={"seed": 25, "max_steps": 5, "noise_per_step": 0})
    for v in env.nodes["web_dmz"].vulnerabilities:
        v.success_prob, v.detection_prob = 1.0, 0.0   # silent break-in
    env.step(red("EXPLOIT", target="web_dmz"), blue("ISOLATE", "workstation"))
    while not env.done:
        env.step(WAIT, MONITOR)
    report = Scorer().final_report(env)
    # workstation isolated for all 5 steps, and it was healthy -> false positive.
    assert report["blue_score"] == -5 * Scorer.DOWNTIME_PENALTY - Scorer.FALSE_POSITIVE_PENALTY
    # web_dmz held undetected for all 5 steps.
    value = env.nodes["web_dmz"].value
    assert report["red_score"] == Scorer.FOOTHOLD_WEIGHT * value + 5 * Scorer.STEALTH_PER_STEP


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
