# purple_sim — autonomous Red vs Blue (Purple Team) simulation

A self-contained research sandbox where an offensive **Red** agent and a
defensive **Blue** agent take turns on an abstract, MITRE ATT&CK–mapped network.
The environment keeps **ground truth hidden** and gives Blue only a **noisy,
delayed telemetry feed**, so "detection" actually means something. A Purple
**coverage report** then correlates what Red really did against what Blue
actually saw and acted on — the honest way, not Blue grading its own homework.

This is a **model**. Nothing touches a real network. Vulnerabilities are
abstract flags; "CVE"/technique labels are just strings used for vocabulary and
scoring. There is no exploit code anywhere in this project.

It borrows one idea each from the main open-source efforts in this space:
abstract network-as-a-game (CyberBattleSim), separate delayed Blue telemetry
(NetForge RL), a turn-based LLM orchestration loop (Kriegsspiel), and ATT&CK
technique IDs as shared vocabulary.

## Quick start (zero dependencies)

```bash
cd purple_sim
python run.py                      # heuristic Red vs heuristic Blue, full trace
python run.py --quiet              # just the final report + coverage
python run.py --episodes 50 --quiet  # batch: win rates + mean coverage
python run.py --episodes 50 --quiet --scenario random  # a different seeded network per game
python tests/test_environment.py   # tests
```

Everything above runs on a stock Python 3.10+ with **no pip installs**.

## The three agent families

All three implement the same tiny contract (`act(view) -> Action`) and share one
environment, so you can mix and match.

| Family | Where | Needs |
|---|---|---|
| **Heuristic** | `agents/heuristic.py` | nothing — deterministic baselines |
| **LLM** | `agents/llm_agents.py` | nothing in *mock* mode; `anthropic` + API key for *live* |
| **RL** | `agents/rl_interface.py` | nothing for the stub; `gymnasium`+`stable-baselines3` to train |

### LLM agents

```bash
python run.py --red llm --blue llm          # mock mode — offline, uses heuristic brain
pip install anthropic
export ANTHROPIC_API_KEY=sk-ant-...
python run.py --red llm --blue llm --live   # real Claude via tool-calling
```

Mock mode builds the *exact* prompt and tool schema the model would receive
(inspect `agent.last_prompt`), then falls back to the heuristic brain to pick the
move — so the full pipeline (orchestrator, scoring, logging) runs unchanged
whether or not a key is present. Live mode forces the model to return a
structured action via tool-calling, not free text.

### RL interface

```bash
python run.py --rl-demo    # random Red agent on the Gym-style env + training notes
```

`PurpleRedEnv` mirrors the `reset()/step()` contract with a flat numeric
observation and a discrete action table, deliberately **without** depending on
gymnasium so the repo stays zero-dep. To train for real, see `train_notes()` —
making it subclass `gymnasium.Env` is a few lines, then PPO drops straight in.

## How a turn works

```
Red picks + resolves its action  ->  emit telemetry (maybe; maybe delayed)
                                 ->  tick restores/patches (finished ones come back online)
                                 ->  emit benign noise, advance the telemetry bus
                                 ->  Blue picks its action from ONLY the visible telemetry
                                     (including events released this step), then it resolves
                                 ->  check termination
```

Red wins by exfiltrating the crown jewel; Blue wins by surviving to `max_steps`.

### Movement rules

- **Red needs a route.** It can only scan or exploit the internet-facing entry
  node, a node it already holds, or a neighbour of a foothold it holds that
  isn't isolated. Knowing a node exists is not enough.
- **LATERAL_MOVE is a credentialed pivot** (T1021): it can take over a
  neighbour even when the neighbour is patched, but it succeeds less often
  (`lateral_success`).
- **Isolation cuts a node off.** Red can't scan, exploit or pivot into it, and
  a foothold on it can't be pivoted from or exfiltrated from.
- **RESTORE re-images.** It evicts Red at once. The node is then offline for
  `restore_duration` Red turns and comes back clean and un-isolated.
- **PATCH needs a maintenance window.** It closes the node's patchable
  vulnerabilities but takes it offline for `patch_duration` Red turns. Stolen
  credentials (T1078 on every entry node) can't be patched, so Blue can slow
  Red's way in but never lock it out for good.
- **Exfiltration takes time.** Red has to EXFILTRATE from the crown jewel for
  `exfil_steps` turns, and a re-image wipes its progress. That window is
  Blue's last chance.
- Isolating an already-isolated node, patching a patched one, or restoring one
  that's already re-imaging is a no-op.

### Scenarios

`--scenario default` is the hand-built 4-node network in `env/scenario.py`.
`--scenario random` generates a different network per seed: 1–2 entry nodes,
3–6 internal hosts with cross-links (so there's usually more than one route),
and the crown jewel behind 1–2 internal hosts, never directly on the DMZ.

## Why the design choices matter

- **Ground truth is private.** `Environment.blue_view()` never exposes a node's
  `compromised` flag or an event's `is_true_positive` label (there's a test for
  this). Blue infers from telemetry alone.
- **Telemetry is noisy and delayed.** Each real attack action is logged only with
  some probability (a blind spot if missed), appears 1–3 steps later, and is
  mixed with benign false positives. Some of that noise *looks* like an attack
  (admin scans, failed logins, legit remote sessions), with the same event kind
  and technique as the real thing, so Blue can't filter it out by type. This is
  what makes the defender's job real.
- **Each side sees its own recent moves.** Both views include the last few
  actions that side took. Red sees its results, but not whether they were
  logged. Blue sees only what it did, never whether a node really was
  compromised.
- **Fair comparisons.** Red's action outcomes, telemetry and noise each draw
  from their own random stream, so two agents run on the same seed face the
  same luck wherever their choices coincide.
- **Containment has a cost.** A containment (isolate/restore) is a true
  positive only if the node was compromised *at the moment Blue acted*.
  Containing a healthy node is a false positive, and every node-step spent
  isolated or re-imaging costs downtime. Blue can't just nuke everything, and
  it can't farm points by re-imaging the same node over and over.
- **Coverage is correlated honestly.** `coverage_pct` = of the attack steps Red
  executed (exploit, lateral move, exfiltrate), how many produced a genuine
  telemetry event that Blue then *responded to* on that host (isolate or
  restore, or patch while the host is still clean; investigate is triage, not a
  response). The response must come at
  or after the step the event became visible. The report also gives
  per-technique coverage and mean time-to-respond.
- **Live LLM fallbacks are visible.** With `--live`, any turn the model didn't
  decide (missing SDK, auth/network error, refusal) is announced and counted at
  the end of the run.

## Tuning the game

Edit `env/scenario.py` (`DEFAULT_CONFIG`) or pass a config dict to `Environment`:

| Knob | Effect |
|---|---|
| `scenario` | `"default"` or `"random"` network |
| `telemetry_latency` | how many steps before Blue sees an event |
| `noise_per_step` | false-positive volume |
| `lookalike_prob` | share of noise that looks like an attack |
| `investigate_boost` | how much INVESTIGATE sharpens future detection |
| `restore_duration` / `patch_duration` | Red turns a node stays offline while re-imaging / patching |
| `lateral_success` / `lateral_detection` | odds a credentialed pivot works / is logged |
| `exfil_steps` / `exfil_detection` | EXFILTRATE turns needed / odds each one is logged |
| `max_steps` | game length / Red's time budget |

Out of the box, heuristic vs heuristic is roughly even. Over 300 games, Red wins
about 46% on the default network and 41% on random ones, and mean coverage is
around 50%. The defaults were tuned for that, so a new agent's win rate against
either baseline means something. The biggest levers are `exfil_steps`
(Blue's window), `telemetry_latency`, and Blue's `CONTAIN_AT` in
`agents/heuristic.py`.

## Layout

```
purple_sim/
  run.py                     # launcher: python run.py
  purple_sim/
    env/
      models.py              # Node, Vulnerability, Action, TelemetryEvent
      attack_catalog.py      # MITRE ATT&CK technique labels
      scenario.py            # default + random networks, config
      telemetry.py           # noisy/delayed Blue feed
      environment.py         # state machine, views, turn resolution
    agents/
      base.py                # RedAgent / BlueAgent interfaces
      heuristic.py           # deterministic baselines
      llm_agents.py          # mock + live Claude agents (tool-calling)
      rl_interface.py        # Gym-style env + RL stub + training notes
    scoring/
      scorer.py              # Red/Blue scores + Purple coverage report
    orchestrator.py          # turn loop + trace + report printing
    cli.py                   # argument parsing / modes
  tests/
    test_environment.py      # rules, scoring and coverage tests (incl. "Blue can't see ground truth")
```

## Next steps

- Add more techniques/nodes in `scenario.py` and `attack_catalog.py`.
- Flip LLM agents to `--live` and compare their coverage against the heuristics.
- Train an RL Red (then an RL Blue) and run self-play.
- Add an LLM-as-judge pass that scores the trace for Red stealth and Blue
  time-to-detect.
