"""Tests — run with: python -m pytest, or just python tests/test_environment.py"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from purple_sim.agents import HeuristicBlue, make_blue, make_red
from purple_sim.agents.rl_interface import PurpleRedEnv, RandomRLAgent
from purple_sim.env.environment import Environment
from purple_sim.env.models import (AccessLevel, Action, BlueActionType, Faction,
                                    Node, RedActionType, Sensor, Vulnerability)
from purple_sim.orchestrator import Orchestrator, SimConfig
from purple_sim.scoring.scorer import Scorer

MONITOR = Action(Faction.BLUE, BlueActionType.MONITOR.value, {})
WAIT = Action(Faction.RED, RedActionType.WAIT.value, {})
ADMIN = int(AccessLevel.ADMIN)


def red(kind, **params):
    return Action(Faction.RED, kind, params)


def blue(kind, target):
    return Action(Faction.BLUE, kind, {"target": target})


def give_foothold(env, name, level=AccessLevel.USER):
    env.red.discovered.add(name)
    env.red.footholds.add(name)
    env.nodes[name].access = int(level)
    env._compromised_at[name] = env.step_count


def mark_scanned(env, name):
    node = env.nodes[name]
    env.red.discovered.add(name)
    env.red.known_vulns[name] = [v.cve_label for v in node.remote_vulns()]
    env.red.known_local[name] = bool(node.local_vulns())


def make_certain(env, name):
    """Exploits/escalations of `name` always land and are always logged."""
    for v in env.nodes[name].vulnerabilities:
        v.success_prob = 1.0
        v.detection_prob = 1.0
    env.nodes[name].sensors = {Sensor.NETWORK: 1.0, Sensor.ENDPOINT: 1.0}


def attack_events(env):
    return [e for e in env.bus._pending + env.bus._visible if e.is_true_positive]


# ----------------------------------------------------------------- basics
def test_stats_intervals_and_significance():
    from purple_sim.stats import (compare_proportions, mean_ci, pct_ci,
                                   wilson_interval)
    lo, hi = wilson_interval(50, 100)
    assert lo < 0.5 < hi and 0.39 < lo < 0.41 and 0.59 < hi < 0.61   # ~[.40,.60]
    assert wilson_interval(0, 10)[0] == 0.0 and wilson_interval(10, 10)[1] >= 0.999
    assert wilson_interval(5, 0) == (0.0, 0.0)                        # no games
    m, lo, hi = mean_ci([10, 10, 10])
    assert m == 10 and lo == 10 and hi == 10                          # no variance
    m, lo, hi = mean_ci([0, 10])
    assert lo < m < hi
    # 90/100 vs 60/100 is a real difference; 52 vs 48 is not.
    assert compare_proportions(90, 100, 60, 100).significant
    assert not compare_proportions(52, 100, 48, 100).significant
    assert "%" in pct_ci(63, 100) and "[" in pct_ci(63, 100)


def test_game_terminates():
    env = Environment(config={"seed": 1, "max_steps": 30})
    report = Orchestrator(env, make_red("heuristic"), make_blue("heuristic"),
                          SimConfig(verbose=False, show_report=False)).run()
    assert env.done
    assert report["winner"] in ("RED", "BLUE")
    assert report["steps"] <= 30


def test_blue_never_sees_ground_truth():
    env = Environment(config={"seed": 2})
    Orchestrator(env, make_red("heuristic"), make_blue("heuristic"),
                 SimConfig(verbose=False, show_report=False)).run()
    view = env.blue_view()
    assert view["telemetry"], "expected telemetry after a full game"
    for node_info in view["nodes"].values():
        assert "compromised" not in node_info and "access" not in node_info
    for event in view["telemetry"]:
        assert "is_true_positive" not in event


def test_exploit_requires_discovery():
    env = Environment(config={"seed": 3})
    result = env.step(red("EXPLOIT", target="db_cluster"), MONITOR)
    assert "not discovered" in result.red_outcome


def test_coverage_is_bounded():
    env = Environment(config={"seed": 4})
    report = Orchestrator(env, make_red("heuristic"), make_blue("heuristic"),
                          SimConfig(verbose=False, show_report=False)).run()
    assert 0.0 <= report["coverage_pct"] <= 100.0


def test_mock_llm_runs_offline():
    env = Environment(config={"seed": 6})
    report = Orchestrator(env, make_red("llm", mock=True), make_blue("llm", mock=True),
                          SimConfig(verbose=False, show_report=False)).run()
    assert report["winner"] in ("RED", "BLUE")


# ----------------------------------------------------------------- movement
def test_red_needs_a_route_not_just_discovery():
    env = Environment(config={"seed": 10})
    env.red.discovered.update({"app_server", "db_cluster"})
    env.red.known_vulns["app_server"] = ["x"]
    r = env.step(red("SCAN", target="db_cluster"), MONITOR)
    assert "no route" in r.red_outcome and not r.red_executed
    r = env.step(red("EXPLOIT", target="app_server"), MONITOR)
    assert "no route" in r.red_outcome and not r.red_executed
    give_foothold(env, "web_dmz")       # neighbour of app_server opens the route
    r = env.step(red("EXPLOIT", target="app_server"), MONITOR)
    assert r.red_executed and "no route" not in r.red_outcome


def test_scan_required_before_exploit():
    env = Environment(config={"seed": 10})
    give_foothold(env, "web_dmz")
    env.red.discovered.add("app_server")   # seen but not fingerprinted
    r = env.step(red("EXPLOIT", target="app_server"), MONITOR)
    assert "SCAN" in r.red_outcome and not r.red_executed
    env.step(red("SCAN", target="app_server"), MONITOR)
    r = env.step(red("EXPLOIT", target="app_server"), MONITOR)
    assert r.red_executed and "SCAN" not in r.red_outcome


def test_exploit_yields_a_foothold_escalate_reaches_admin():
    env = Environment(config={"seed": 10})
    give_foothold(env, "web_dmz")
    mark_scanned(env, "app_server")
    env.nodes["app_server"].vulnerabilities[0].success_prob = 1.0   # remote RCE -> USER
    for v in env.nodes["app_server"].local_vulns():
        v.success_prob = 1.0                                        # privesc -> ADMIN
    env.step(red("EXPLOIT", target="app_server"), MONITOR)
    assert env.nodes["app_server"].access == AccessLevel.USER
    env.step(red("ESCALATE", target="app_server"), MONITOR)
    assert env.nodes["app_server"].access == AccessLevel.ADMIN


def test_crossing_into_secure_needs_admin_on_the_pivot():
    env = Environment(config={"seed": 10, "lateral_success": 1.0})
    give_foothold(env, "app_server", AccessLevel.USER)   # internal, next to secure db
    env.red.discovered.add("db_cluster")
    assert not env.red_view()["nodes"]["db_cluster"]["reachable"]   # USER can't cross
    r = env.step(red("LATERAL_MOVE", source="app_server", target="db_cluster"), MONITOR)
    assert "needs ADMIN" in r.red_outcome and not r.red_executed
    env.nodes["app_server"].access = int(AccessLevel.ADMIN)
    r = env.step(red("LATERAL_MOVE", source="app_server", target="db_cluster"), MONITOR)
    assert r.red_executed and "db_cluster" in env.red.footholds


def test_firewall_blocks_a_disallowed_segment_hop():
    rce = Vulnerability("T1190", "x", "CVE-X", 1.0, 0.0, service="http")
    a = Node("a", segment="dmz", is_entry=True, connections=["b"], vulnerabilities=[rce])
    b = Node("b", segment="secure", is_crown_jewel=True, connections=["a"],
             vulnerabilities=[Vulnerability("T1210", "y", "CVE-Y", 1.0, 0.0)])
    env = Environment(network={"a": a, "b": b}, firewall={"internet": {"dmz"}, "dmz": set()},
                      config={"analyst_budget": 0})
    give_foothold(env, "a", AccessLevel.ADMIN)
    env.red.discovered.add("b")
    r = env.step(red("LATERAL_MOVE", source="a", target="b"), MONITOR)
    assert "firewall blocks dmz->secure" in r.red_outcome and not r.red_executed


def test_isolated_foothold_cannot_pivot_or_exfiltrate():
    env = Environment(config={"seed": 11})
    give_foothold(env, "app_server", AccessLevel.USER)
    give_foothold(env, "db_cluster", AccessLevel.ADMIN)
    env.nodes["db_cluster"].isolated = True
    r = env.step(red("EXFILTRATE", target="db_cluster"), MONITOR)
    assert "blocked" in r.red_outcome and not env.red_exfiltrated
    env.nodes["app_server"].isolated = True
    r = env.step(red("LATERAL_MOVE", source="app_server", target="workstation"), MONITOR)
    assert "isolated" in r.red_outcome and not r.red_executed


# ----------------------------------------------------------------- blue actions
def test_restore_takes_node_offline_then_returns_it_clean():
    env = Environment(config={"seed": 12, "restore_duration": 2})
    give_foothold(env, "web_dmz")
    mark_scanned(env, "web_dmz")
    env.nodes["web_dmz"].isolated = True
    env.step(WAIT, blue("RESTORE", "web_dmz"))
    assert "web_dmz" not in env.red.footholds
    for _ in range(2):
        r = env.step(red("EXPLOIT", target="web_dmz"), MONITOR)
        assert "offline" in r.red_outcome
    node = env.nodes["web_dmz"]
    assert node.restoring == 0 and not node.isolated
    r = env.step(red("EXPLOIT", target="web_dmz"), MONITOR)
    assert "offline" not in r.red_outcome


def test_patch_has_a_maintenance_window_and_skips_unpatchable_vulns():
    env = Environment(config={"seed": 21, "patch_duration": 1})
    mark_scanned(env, "web_dmz")
    r = env.step(WAIT, blue("PATCH", "web_dmz"))
    assert r.blue_effective and r.offline_nodes == 1
    r = env.step(red("EXPLOIT", target="web_dmz"), MONITOR)
    assert "offline" in r.red_outcome
    open_techs = {v.technique_id for v in env.nodes["web_dmz"].open_vulns()}
    assert open_techs == {"T1078"}           # unpatchable stolen credentials survive
    r = env.step(WAIT, blue("PATCH", "web_dmz"))
    assert not r.blue_effective


def test_analyst_budget_caps_blue_actions():
    env = Environment(config={"seed": 12, "analyst_budget": 3})  # RESTORE costs 3
    r = env.step(WAIT, blue("RESTORE", "web_dmz"))
    assert r.blue_effective and env.analyst_remaining == 0
    r = env.step(WAIT, blue("RESTORE", "app_server"))
    assert "no analyst capacity" in r.blue_outcome and not r.blue_effective
    assert env.blue_view()["analyst_remaining"] == 0


def test_repeated_restores_of_a_clean_node_are_false_positives():
    env = Environment(config={"seed": 13, "max_steps": 20, "analyst_budget": 0})
    make_certain(env, "web_dmz")
    mark_scanned(env, "web_dmz")
    env.step(red("EXPLOIT", target="web_dmz"), MONITOR)
    while not env.done:
        env.step(WAIT, blue("RESTORE", "web_dmz"))
    report = Scorer().final_report(env)
    assert report["true_positives"] == 1
    assert report["false_positives"] >= 5
    assert report["blue_score"] < 0


# ----------------------------------------------------------------- telemetry
def test_blue_decides_on_telemetry_released_this_step():
    env = Environment(config={"seed": 14, "telemetry_latency": (1, 1), "noise_per_step": 0})
    make_certain(env, "web_dmz")
    mark_scanned(env, "web_dmz")
    env.step(red("EXPLOIT", target="web_dmz"), MONITOR)
    seen = []
    env.step(WAIT, lambda view: seen.extend(view["telemetry"]) or MONITOR)
    assert any(e["kind"] == "EXPLOIT_ATTEMPT" and e["step"] == "1" for e in seen)


def test_sensor_blind_spot_hides_until_investigated():
    # workstation has no ENDPOINT sensor, so exploit attempts there go unlogged...
    env = Environment(config={"seed": 18, "noise_per_step": 0})
    give_foothold(env, "app_server")
    mark_scanned(env, "workstation")
    env.nodes["workstation"].vulnerabilities[0].success_prob = 1.0
    env.nodes["workstation"].vulnerabilities[0].detection_prob = 1.0
    env.step(red("EXPLOIT", target="workstation"), MONITOR)
    assert not [e for e in attack_events(env) if e.node == "workstation"]
    # ...until Blue raises monitoring on it (which works even with no sensor).
    for _ in range(3):
        env.nodes["workstation"].monitoring = min(1.0, env.nodes["workstation"].monitoring + 0.4)
    env.step(red("EXPLOIT", target="workstation"), MONITOR)
    assert [e for e in attack_events(env)
            if e.node == "workstation" and e.kind == "EXPLOIT_ATTEMPT"]


def test_log_retention_scrolls_events_off_blues_view_but_not_the_record():
    env = Environment(config={"seed": 19, "log_retention": 3, "telemetry_latency": (1, 1),
                              "noise_per_step": 0})
    make_certain(env, "web_dmz")
    mark_scanned(env, "web_dmz")
    env.step(red("EXPLOIT", target="web_dmz"), MONITOR)   # event at step 1, visible step 2
    for _ in range(5):
        if not env.done:
            env.step(WAIT, MONITOR)
    working = env.blue_view()["telemetry"]
    assert not any(e["kind"] == "EXPLOIT_ATTEMPT" for e in working)      # scrolled off
    assert any(e.node == "web_dmz" and e.is_true_positive for e in env.bus.visible_events())


def test_some_noise_looks_like_an_attack_but_is_a_false_positive():
    env = Environment(config={"seed": 20, "noise_per_step": 3, "lookalike_prob": 0.5,
                              "max_steps": 20})
    while not env.done:
        env.step(WAIT, MONITOR)
    lookalikes = [e for e in env.bus.visible_events() if e.kind != "BENIGN_NOISE"]
    assert lookalikes and not any(e.is_true_positive for e in lookalikes)
    for e in lookalikes:
        if e.kind == "EXPLOIT_ATTEMPT":
            assert e.technique_id == env.nodes[e.node].vulnerabilities[0].technique_id


def test_stealth_mode_trades_success_for_lower_detection():
    def rates(stealth, n=300):
        logged = succ = 0
        for s in range(n):
            env = Environment(config={"seed": 1000 + s, "noise_per_step": 0})
            mark_scanned(env, "web_dmz")
            v = env.nodes["web_dmz"].remote_vulns()[0]
            v.success_prob, v.detection_prob = 0.8, 1.0
            env.nodes["web_dmz"].sensors[Sensor.ENDPOINT] = 1.0
            params = {"target": "web_dmz"}
            if stealth:
                params["mode"] = "stealth"
            env.step(red("EXPLOIT", **params), MONITOR)
            logged += any(e.node == "web_dmz" and e.kind == "EXPLOIT_ATTEMPT"
                          for e in attack_events(env))
            succ += "SUCCESS" in env.history[0].red_feedback
        return logged / n, succ / n
    loud_logged, loud_succ = rates(False)
    quiet_logged, quiet_succ = rates(True)
    assert quiet_logged < loud_logged - 0.3     # much quieter
    assert quiet_succ < loud_succ               # but less reliable


def test_a_host_without_a_sensor_never_raises_that_sensors_alerts():
    # Default workstation has no ENDPOINT sensor: no EDR alerts from it, benign or not.
    env = Environment(config={"seed": 32, "noise_per_step": 6, "lookalike_prob": 1.0,
                              "max_steps": 30})
    while not env.done:
        env.step(WAIT, MONITOR)
    ws = [e for e in env.bus.visible_events() if e.node == "workstation"]
    assert ws, "expected some (network) noise on the workstation"
    assert not any(e.sensor == "ENDPOINT" for e in ws)
    assert any(e.sensor == "ENDPOINT" for e in env.bus.visible_events())  # others still do


# ----------------------------------------------------------------- scoring / coverage
def test_coverage_counts_only_responses_after_the_event_is_visible():
    cfg = {"seed": 15, "telemetry_latency": (2, 2), "noise_per_step": 0, "analyst_budget": 0}

    def exploited_web():
        e = Environment(config=cfg)
        make_certain(e, "web_dmz")
        mark_scanned(e, "web_dmz")
        return e

    env = exploited_web()
    env.step(red("EXPLOIT", target="web_dmz"), blue("ISOLATE", "web_dmz"))  # acts too early
    env.step(WAIT, MONITOR)
    env.step(WAIT, MONITOR)
    row = Scorer().final_report(env)["coverage_rows"][0]
    assert row["in_telemetry"] and row["seen_at"] == 3 and not row["detected"]

    env = exploited_web()
    env.step(red("EXPLOIT", target="web_dmz"), MONITOR)
    env.step(WAIT, MONITOR)
    env.step(WAIT, blue("INVESTIGATE", "web_dmz"))          # triage, not a response
    assert not Scorer().final_report(env)["coverage_rows"][0]["detected"]

    env = exploited_web()
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
    env.step(red("SCAN", target="app_server"), MONITOR)
    env.step(red("EXPLOIT", target="app_server"), MONITOR)
    rows = [r for r in Scorer().final_report(env)["coverage_rows"] if r["action"] == "EXPLOIT"]
    assert rows and rows[0]["technique"] == "T1210"


def test_downtime_and_stealth_are_scored():
    env = Environment(config={"seed": 25, "max_steps": 5, "noise_per_step": 0,
                              "analyst_budget": 0})
    for v in env.nodes["web_dmz"].vulnerabilities:
        v.success_prob, v.detection_prob = 1.0, 0.0
    mark_scanned(env, "web_dmz")
    env.step(red("EXPLOIT", target="web_dmz"), blue("ISOLATE", "workstation"))
    while not env.done:
        env.step(WAIT, MONITOR)
    report = Scorer().final_report(env)
    assert report["blue_score"] == -5 * Scorer.DOWNTIME_PENALTY - Scorer.FALSE_POSITIVE_PENALTY
    value = env.nodes["web_dmz"].value
    assert report["red_score"] == Scorer.FOOTHOLD_WEIGHT * value + 5 * Scorer.STEALTH_PER_STEP


def test_winning_outscores_stealth_farming_and_exfil_credit_is_revocable():
    env = Environment()
    max_stealth = Scorer.STEALTH_PER_STEP * len(env.nodes) * env.max_steps
    assert Scorer.EXFIL_BONUS > max_stealth
    env = Environment(config={"seed": 30, "exfil_steps": 3})
    give_foothold(env, "app_server", AccessLevel.USER)
    give_foothold(env, "db_cluster", AccessLevel.ADMIN)
    base = Scorer().score_state(env)["red"]
    env.step(red("EXFILTRATE", target="db_cluster"), MONITOR)
    assert Scorer().score_state(env)["red"] > base
    env.step(WAIT, blue("RESTORE", "db_cluster"))
    after = Scorer().score_state(env)["red"]
    assert after == base - Scorer.FOOTHOLD_WEIGHT * env.nodes["db_cluster"].value


def test_exfiltration_takes_several_turns_and_restore_wipes_progress():
    exfil = red("EXFILTRATE", target="db_cluster")
    env = Environment(config={"seed": 22, "exfil_steps": 3})
    give_foothold(env, "db_cluster", AccessLevel.ADMIN)
    env.step(exfil, MONITOR)
    env.step(exfil, blue("RESTORE", "db_cluster"))
    assert not env.red_exfiltrated and "db_cluster" not in env.exfil_progress
    env = Environment(config={"seed": 22, "exfil_steps": 3})
    give_foothold(env, "db_cluster", AccessLevel.ADMIN)
    for _ in range(3):
        env.step(exfil, MONITOR)
    assert env.red_exfiltrated and env.winner == "RED"


# ----------------------------------------------------------------- determinism / views
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
    mark_scanned(env, "web_dmz")
    env.step(red("EXPLOIT", target="web_dmz"), blue("RESTORE", "app_server"))
    red_hist = env.red_view()["recent_actions"]
    assert red_hist and "SUCCESS" in red_hist[0]["result"]
    assert "logged" not in red_hist[0]["result"] and "undetected" not in red_hist[0]["result"]
    assert env.blue_view()["recent_actions"] == [{"step": 1, "action": "RESTORE app_server"}]


def test_random_networks_are_seeded_and_winnable():
    from purple_sim.env.scenario import ADMIN_SEGMENTS, FIREWALL, random_network
    for seed in range(50):
        net = random_network(seed)
        assert net.keys() == random_network(seed).keys()
        entries = [n for n, node in net.items() if node.is_entry]
        jewel = next(n for n, node in net.items() if node.is_crown_jewel)
        assert entries and not any(jewel in net[e].connections for e in entries)
        for a, node in net.items():
            assert all(a in net[b].connections for b in node.connections)
        # Jewel reachable from an entry through firewall-allowed segment hops.
        seen, frontier = set(entries), list(entries)
        while frontier:
            cur = frontier.pop()
            for nb in net[cur].connections:
                if nb not in seen and net[nb].segment in FIREWALL.get(net[cur].segment, set()):
                    seen.add(nb)
                    frontier.append(nb)
        assert jewel in seen
        assert net[jewel].segment in ADMIN_SEGMENTS
    assert any(len(random_network(s)) != len(random_network(0)) for s in range(1, 20))


# ----------------------------------------------------------------- RL
def test_rl_env_runs():
    env = PurpleRedEnv(seed=5)
    obs = env.reset()
    assert len(obs) == env.obs_dim
    agent = RandomRLAgent(env, seed=5)
    done, steps = False, 0
    while not done and steps < 200:
        obs, reward, done, info = env.step(agent.act(obs))
        steps += 1
    assert done


def test_milestone_shaping_potential():
    from purple_sim.agents.rl_interface import (ADMIN_MILESTONE, SECURE_MILESTONE,
                                                milestone_potential)
    env = Environment(config={"seed": 33})
    assert milestone_potential(env) == 0
    give_foothold(env, "app_server", AccessLevel.ADMIN)
    assert milestone_potential(env) == ADMIN_MILESTONE * env.nodes["app_server"].value
    give_foothold(env, "db_cluster", AccessLevel.USER)      # inside the secure zone
    assert milestone_potential(env) == (ADMIN_MILESTONE * env.nodes["app_server"].value
                                        + SECURE_MILESTONE)
    env.step(WAIT, blue("RESTORE", "db_cluster"))           # eviction takes it back
    assert milestone_potential(env) == ADMIN_MILESTONE * env.nodes["app_server"].value
    shaped = PurpleRedEnv(seed=34, shaping=True)
    shaped.reset()
    _, reward, _, _ = shaped.step(0)
    assert isinstance(reward, float)


def test_rl_episodes_use_fresh_seeds():
    env = PurpleRedEnv(seed=27)
    env.reset()
    first = env.env.config["seed"]
    env.reset()
    assert env.env.config["seed"] != first


def test_policy_red_plays_in_the_orchestrator():
    from purple_sim.agents import PolicyRed
    from purple_sim.env.scenario import default_network
    always_wait = PolicyRed(lambda obs, mask: 0, default_network())
    env = Environment(config={"seed": 28})
    report = Orchestrator(env, always_wait, make_blue("heuristic"),
                          SimConfig(verbose=False, show_report=False)).run()
    assert report["winner"] == "BLUE"
    assert all(h.red_action.type == "WAIT" for h in env.history)


def test_every_unmasked_move_reaches_the_network():
    import random
    rng = random.Random(31)
    for seed in range(20):
        env = PurpleRedEnv(seed=seed)
        env.reset()
        done = False
        while not done:
            valid = [i for i, ok in enumerate(env.action_mask()) if ok]
            idx = rng.choice(valid)
            action = env.action_table[idx]
            before = len(env.env.history)
            _, _, done, _ = env.step(idx)
            rec = env.env.history[before]
            assert action.type == "WAIT" or rec.red_executed, (str(action), rec.red_outcome)


def test_gym_adapter_passes_gymnasium_checks():
    try:
        from gymnasium.utils.env_checker import check_env
        from purple_sim.agents.gym_env import GymBlueEnv, GymRedEnv
    except ImportError:
        print("  (skipped: gymnasium not installed)")
        return
    check_env(GymRedEnv(seed=29), skip_render_check=True)
    check_env(GymBlueEnv(seed=29), skip_render_check=True)


def test_blue_rl_env_runs_and_masks_are_valid():
    from purple_sim.agents.blue_rl import PurpleBlueEnv
    env = PurpleBlueEnv(seed=41)
    obs = env.reset()
    assert len(obs) == env.obs_dim
    done, steps = False, 0
    while not done and steps < 200:
        mask = env.action_mask()
        assert mask[0] and any(mask)          # MONITOR always available
        obs, reward, done, info = env.step(mask.index(True))
        steps += 1
    assert done


def test_blue_rl_reward_sums_to_the_honest_blue_score():
    # The learner optimises the real metric: summed step reward == final blue_score.
    import random
    from purple_sim.agents.blue_rl import PurpleBlueEnv
    rng = random.Random(44)
    env = PurpleBlueEnv(seed=44)
    env.reset()
    total, done = 0.0, False
    while not done:
        mask = env.action_mask()
        idx = rng.choice([i for i, ok in enumerate(mask) if ok])
        _, reward, done, _ = env.step(idx)
        total += reward
    assert abs(total - Scorer().final_report(env.env)["blue_score"]) < 1e-6


def test_policy_blue_plays_in_the_orchestrator():
    from purple_sim.agents.blue_rl import PolicyBlue
    from purple_sim.env.scenario import default_network
    # A policy that always MONITORs (index 0) should let Red win eventually.
    passive = PolicyBlue(lambda obs, mask: 0, default_network(), budget_on=True)
    env = Environment(config={"seed": 42})
    report = Orchestrator(env, make_red("heuristic"), passive,
                          SimConfig(verbose=False, show_report=False)).run()
    assert report["winner"] in ("RED", "BLUE")
    assert all(h.blue_action.type == "MONITOR" for h in env.history)


# ----------------------------------------------------------------- agents
def test_heuristic_red_reaches_admin_and_exfiltrates_sometimes():
    wins = 0
    for seed in range(40):
        env = Environment(config={"seed": 100 + seed})
        report = Orchestrator(env, make_red("heuristic"), make_blue("heuristic"),
                              SimConfig(verbose=False, show_report=False)).run()
        wins += report["winner"] == "RED"
    assert wins > 0   # the kill chain can actually complete


def test_archetype_scenarios_build_and_terminate():
    from purple_sim.env.scenario import SCENARIOS
    for scenario in SCENARIOS:
        env = Environment(config={"seed": 3, "scenario": scenario})
        jewels = [n for n, node in env.nodes.items() if node.is_crown_jewel]
        entries = [n for n, node in env.nodes.items() if node.is_entry]
        assert len(jewels) == 1 and entries, scenario
        report = Orchestrator(env, make_red("heuristic"), make_blue("soc"),
                              SimConfig(verbose=False, show_report=False)).run()
        assert report["winner"] in ("RED", "BLUE"), scenario


def test_soc_blue_runs_and_respects_budget_and_ground_truth():
    env = Environment(config={"seed": 40, "analyst_budget": 6})
    report = Orchestrator(env, make_red("heuristic"), make_blue("soc"),
                          SimConfig(verbose=False, show_report=False)).run()
    assert report["winner"] in ("RED", "BLUE")
    assert env.analyst_remaining >= 0            # never overspent the budget
    for info in env.blue_view()["nodes"].values():
        assert "access" not in info               # still no ground-truth leak


def test_heuristic_blue_does_not_refixate_after_restore():
    agent = HeuristicBlue()
    alerts = [{"step": "1", "kind": "LATERAL_DETECTED", "node": "workstation"}] * 2

    def view(step, isolated=False, restoring=False):
        nodes = {"workstation": {"is_crown_jewel": False, "isolated": isolated,
                                 "restoring": restoring}}
        return {"step": step, "nodes": nodes, "telemetry": alerts,
                "analyst_budget": 0, "analyst_remaining": 0}

    assert agent.act(view(2)).type == "ISOLATE"
    assert agent.act(view(3, isolated=True)).type == "RESTORE"
    assert agent.act(view(6)).type not in ("ISOLATE", "RESTORE")


def test_llm_prompt_caps_telemetry():
    from purple_sim.agents.llm_agents import MAX_TELEMETRY_IN_PROMPT
    env = Environment(config={"seed": 26, "noise_per_step": 8, "max_steps": 20,
                              "log_retention": 0})
    while not env.done:
        env.step(WAIT, MONITOR)
    agent = make_blue("llm", mock=True)
    agent.act(env.blue_view())
    assert len(env.blue_view()["telemetry"]) > MAX_TELEMETRY_IN_PROMPT
    assert "older telemetry events omitted" in agent.last_prompt
    assert agent.last_prompt.count('"kind"') == MAX_TELEMETRY_IN_PROMPT


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
        passed += 1
    print(f"\n{passed}/{len(tests)} tests passed.")
