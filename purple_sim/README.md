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
| **RL** | `agents/rl_interface.py`, `agents/gym_env.py`, `train_rl.py` | nothing for the stub; `gymnasium` + `stable-baselines3` + `sb3-contrib` to train |

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

The system prompts explain the game's rules and costs, each turn's prompt
includes that side's own recent moves, and telemetry in the prompt is capped to
the most recent 40 events. Live mode uses `claude-opus-4-8`. Moving to
`claude-opus-5-5` means replacing the forced `tool_choice` (which that model
rejects) with `tool_choice: auto` plus `strict: true` on the tools.

### RL interface

```bash
python run.py --rl-demo    # random Red agent on the Gym-style env + training notes

pip install gymnasium stable-baselines3 sb3-contrib
python train_rl.py                                    # train PPO Red, compare with baselines
python run.py --red rl --rl-model models/ppo_red.zip  # watch the trained agent play
```

`PurpleRedEnv` mirrors the `reset()/step()` contract with a flat numeric
observation and a discrete action table, deliberately **without** depending on
gymnasium so the core stays zero-dep. `agents/gym_env.py` wraps it as a real
`gymnasium.Env`, and `PolicyRed` plays any trained policy as a normal Red
agent in the orchestrator.

- **Every episode is a new game.** Each reset draws a fresh seed, so the
  learner can't memorise one run.
- **Reward:** the change in Red's position each step (footholds weighted by
  value, partial credit for exfiltration progress, +100 for the steal, negative
  when evicted), +0.2 per foothold Blue hasn't seen yet, and −0.1 for a move
  that didn't reach the network. Stealth is deliberately small. An earlier
  version paid +1 per hidden foothold per turn, and PPO learned to sit on
  footholds farming it instead of ever stealing the data.
- **Observation:** per node — discovered, reachable, held, access level,
  isolated, scanned, has known vulns, can escalate, is the crown jewel, and how
  far exfiltration has got.
- **Action masking:** each turn the learner is told which moves can do
  anything, worked out from Red's own view so it reveals nothing new. Training
  uses MaskablePPO from `sb3-contrib`. Without masking, plain PPO never found
  the multi-step chain (scan → exploit → escalate → pivot → exfil).
- **Default network only.** The observation and action table are built from a
  fixed node set, so RL uses the default scenario.

Reference result (`train_rl.py`, 600k steps on CPU, 300 held-out games vs the
heuristic Blue, default network): MaskablePPO Red ~39% wins / 36% Blue coverage,
heuristic Red ~37% / 38%, random valid-move Red ~0%. On this deeper model the
full chain (scan → exploit → escalate → pivot → exfil) is harder to learn, so
PPO only edges the scripted baseline at 600k steps but is already stealthier
(lower coverage). Longer training widens the gap; `train_rl.py` prints the
table so you can see where your run landed.

## How a turn works

```
Red picks + resolves its action  ->  emit telemetry (maybe; maybe delayed)
                                 ->  tick restores/patches (finished ones come back online)
                                 ->  emit benign noise, advance the telemetry bus
                                 ->  Blue picks its action from ONLY the visible telemetry
                                     (including events released this step), then it resolves
                                 ->  check termination
```

Red wins by exfiltrating the crown jewel; Blue wins by surviving to `max_steps`
without that happening.

### The attack chain

Access on a host is **NONE < USER < ADMIN**. Red works a kill chain:

1. **SCAN** a reachable node — reveals its remote vulnerabilities, whether it
   has a local privilege-escalation path, and its neighbours. You can't EXPLOIT
   what you haven't scanned.
2. **EXPLOIT** a known remote vuln for a foothold (usually USER).
3. **ESCALATE** USER → ADMIN using a local privesc path. ADMIN is needed to
   cross into a secure segment and to exfiltrate.
4. **LATERAL_MOVE** from a foothold to an adjacent node (`lateral_from` lists
   the sources that can legally reach a node now).
5. **EXFILTRATE** from the crown jewel at ADMIN, for `exfil_steps` turns; a
   re-image wipes the progress.

### Movement rules

- **Red needs a route.** It can only act on the internet-facing entry node, a
  node it holds, or a neighbour of a non-isolated foothold — and only where the
  **firewall** permits that segment hop.
- **Segments + firewall.** Hosts live in zones (`dmz`, `internal`, `secure`).
  Traffic is allowed only between the segment pairs in `FIREWALL`. Crossing into
  an `ADMIN_SEGMENT` (the `secure` zone) requires **ADMIN** on the pivot host —
  so reaching the crown jewel forces an ESCALATE, not just a lucky path.
- **Isolation cuts a node off.** Red can't scan, exploit, escalate on, or pivot
  into/out of it.
- **RESTORE re-images.** Evicts Red at once; the node is offline for
  `restore_duration` turns, then returns clean and un-isolated.
- **PATCH needs a maintenance window.** Closes patchable vulns but takes the
  node offline for `patch_duration` turns. Stolen credentials (T1078 on every
  entry node) and the firewall can't be patched away, so Blue can slow Red's way
  in but never lock it out for good.
- Isolating an already-isolated node, patching a patched one, or restoring one
  that's already re-imaging is a no-op.

### Detection: sensors, blind spots, retention

Every attack action would be picked up by one sensor — **NETWORK** (scans,
lateral movement) or **ENDPOINT** (exploitation, privesc, exfil). Each host has
a coverage level per sensor; the chance an action is logged is its base
detection × that coverage, plus any INVESTIGATE monitoring (which works even
where a sensor is **absent** — a zero-coverage host is a blind spot, e.g. the
default `workstation` has no EDR). Blue only acts on events inside a
`log_retention` window; older ones scroll off its working view (but stay in the
record the Purple report is scored against).

### Defender budget

Blue has a finite pool of **analyst action-points** (`analyst_budget`) for the
whole game. INVESTIGATE/PATCH/ISOLATE/RESTORE each cost points; once the pool is
empty Blue can only MONITOR. False positives and needless containment burn the
budget, so a trigger-happy Blue runs dry before the real intrusion lands.

### Scenarios

`--scenario default` is the hand-built 4-node network in `env/scenario.py`.
`--scenario random` generates a different network per seed: 1–2 entry nodes,
3–6 internal hosts with cross-links (so there's usually more than one route),
per-host sensor coverage (some with blind spots), and the crown jewel in the
`secure` segment behind 1–2 internal hosts, never directly on the DMZ.

## Why the design choices matter

- **Ground truth is private.** `Environment.blue_view()` never exposes a node's
  `compromised` flag or an event's `is_true_positive` label (there's a test for
  this). Blue infers from telemetry alone.
- **Telemetry is noisy, delayed and patchy.** A real attack action is logged
  only with some probability (set by the host's sensor coverage — zero is a
  blind spot), appears 1–3 steps later, scrolls off after `log_retention`
  steps, and is mixed with benign false positives. Some of that noise *looks*
  like an attack (admin scans, failed logins, legit remote sessions), with the
  same event kind and technique as the real thing, so Blue can't filter it out
  by type. This is what makes the defender's job real.
- **Each side sees its own recent moves.** Both views include the last few
  actions that side took. Red sees its results, but not whether they were
  logged. Blue sees only what it did, never whether a node really was
  compromised.
- **Fair comparisons.** Red's action outcomes, telemetry and noise each draw
  from their own random stream, so two agents run on the same seed face the
  same luck wherever their choices coincide.
- **Containment has a cost, and attention is finite.** A containment
  (isolate/restore) is a true positive only if the node was compromised *at the
  moment Blue acted*. Containing a healthy node is a false positive; every
  node-step offline costs downtime; and every active move spends from a fixed
  analyst-point budget. Blue can't just nuke everything or chase every alert.
- **Coverage is correlated honestly.** `coverage_pct` = of the attack steps Red
  executed (exploit, escalate, lateral move, exfiltrate), how many produced a genuine
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
| `noise_per_step` / `lookalike_prob` | false-positive volume / share that looks like an attack |
| `log_retention` | steps an event stays in Blue's working view (0 = forever) |
| `investigate_boost` | how much INVESTIGATE sharpens future detection |
| `restore_duration` / `patch_duration` | Red turns a node stays offline while re-imaging / patching |
| `escalate_detection` | odds an ESCALATE is logged |
| `lateral_success` / `lateral_detection` | odds a pivot works / is logged |
| `exfil_steps` / `exfil_detection` | EXFILTRATE turns needed / odds each one is logged |
| `analyst_budget` + `analyst_costs` | Blue's total action-points and per-action cost |
| `max_steps` | game length / Red's time budget |

Out of the box, heuristic vs heuristic is roughly even on the default network
(over 300 games, Red wins ~45%, mean coverage ~36%). Random networks are harder
for the defender — more hosts, more blind spots, longer paths — so Red wins
~63% there; that gap is a finding, not a bug. The defaults were tuned for the
default network, so a new agent's win rate against either baseline means
something. The biggest levers are `analyst_budget` (how much Blue can do),
`exfil_steps` (Blue's window), `log_retention`, and Blue's `CONTAIN_AT` in
`agents/heuristic.py`.

## Layout

```
purple_sim/
  run.py                     # launcher: python run.py
  train_rl.py                # train + evaluate a MaskablePPO Red (needs gymnasium + SB3 + sb3-contrib)
  purple_sim/
    env/
      models.py              # Node, Vulnerability, Action, TelemetryEvent, AccessLevel, Sensor
      attack_catalog.py      # MITRE ATT&CK technique labels
      scenario.py            # default + random networks, config
      telemetry.py           # noisy/delayed Blue feed
      environment.py         # state machine, views, turn resolution
    agents/
      base.py                # RedAgent / BlueAgent interfaces
      heuristic.py           # deterministic baselines
      llm_agents.py          # mock + live Claude agents (tool-calling)
      rl_interface.py        # zero-dep Gym-style env, PolicyRed, RL stub
      gym_env.py             # gymnasium adapter + loading a trained policy
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
- Train an RL Blue against the PPO Red and alternate (self-play).
- Make RL work on random networks (a fixed-size, role-indexed node encoding).
- Add an LLM-as-judge pass that scores the trace for Red stealth and Blue
  time-to-detect.
