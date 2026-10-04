# Detection-coverage analysis on a representative enterprise network

**What this is.** A worked analysis using `purple_sim` on the built-in
`enterprise` scenario — a *representative* multi-tier network, **not** any real
environment. It shows the kind of defensive insight the model produces and
which levers matter, in a form you can re-run after editing the scenario to
resemble your own site. Nothing here touches a real system.

> This report was revised after two corrections to the model and method (see
> *Corrections* at the end). The earlier version's headline — "analyst capacity
> is the bottleneck" — turned out to be an artifact of a weak defender. Treated
> honestly below.

Reproduce:

```bash
python run.py --analyze --scenario enterprise --episodes 400 --quiet            # heuristic Blue
python run.py --analyze --scenario enterprise --episodes 400 --quiet --blue soc # smarter Blue
```

## The modelled network

9 hosts in three firewalled zones; the database (crown jewel) sits in `secure`
and is reachable only with admin on an internal pivot.

```
internet
  │
[dmz]  web_proxy ── app_server ── db_cluster*      (* crown jewel)
       vpn_gateway ─ jump_host ──┘
                         │
[internal]  domain_controller ── file_server ── workstation_eng
                                              └ workstation_hr
```

Endpoint (EDR) coverage is uneven and realistic: strong on the domain
controller and database, medium on servers, **none on the two workstations**,
weak on the file server. Network-sensor coverage is 0.5–0.8 everywhere.

## Finding 1 — the defender matters more than any single control

Same network, same attacker, two scripted defenders. `HeuristicBlue` reacts to
the single hottest host; `SOCBlue` weights alerts by recency and severity,
correlates across neighbours, compensates for blind spots, and rations its
analyst budget.

| Defender | Red win % | mean coverage % |
|---|---|---|
| HeuristicBlue | 63 | 31 |
| SOCBlue | **44** | 30 |

Swapping to a budget-disciplined analyst — no new sensors, no bigger budget —
drops Red's win rate by a third. **Who is operating the controls dominates the
result.** Any claim about "which control to buy" is downstream of this.

## Finding 2 — the top lever depends on the defender

Each row changes one thing from the baseline and re-runs 300 games. "workstn %"
is mean coverage across the two (EDR-less) workstations.

**HeuristicBlue (reacts to the hottest host, wastes budget on noise):**

| Intervention | Red win % | coverage % | workstn % | T1078 % | file % |
|---|---|---|---|---|---|
| baseline | 63 | 31 | 2 | 3 | 24 |
| + EDR on workstations | 68 | 30 | 2 | 2 | 25 |
| + EDR on file_server | 66 | 31 | 1 | 2 | 33 |
| faster logs (latency 1) | 59 | 31 | 5 | 5 | 21 |
| **bigger SOC (budget 80)** | **44** | 36 | 3 | 5 | 29 |
| everything combined | 14 | 41 | 28 | 33 | 43 |

**SOCBlue (recency/severity, correlation, budget-disciplined):**

| Intervention | Red win % | coverage % | workstn % | T1078 % | file % |
|---|---|---|---|---|---|
| baseline | 44 | 30 | 5 | 7 | 14 |
| + EDR on workstations | 45 | 31 | **18** | 13 | 17 |
| + EDR on file_server | 45 | 30 | 6 | 9 | 21 |
| **faster logs (latency 1)** | **7** | 39 | 10 | 15 | 27 |
| bigger SOC (budget 80) | 44 | 30 | 5 | 7 | 14 |
| everything combined | 7 | 43 | 24 | 25 | 42 |

For the weak defender the binding constraint is **analyst capacity** (it burns
its budget chasing noise, so a bigger budget helps most: 63→44). For the
competent defender a bigger budget does **nothing** (44→44) — it was never
capacity-starved — and the decisive lever is **log latency**: cutting detection
delay collapses Red's win rate from 44% to 7%. Same network, opposite advice,
depending on how good your SOC already is.

## Finding 3 — sensors buy visibility, not necessarily outcomes

Adding EDR to the blind workstations, with the competent defender, raised
**workstation coverage from 5% to 18%** — it genuinely sees more. But the win
rate didn't move (44→45), because those workstations aren't on the critical
path to the crown jewel. Visibility where the attacker isn't going improves
your coverage metric without improving the outcome. **Sensor placement relative
to the attack path matters more than sensor count.**

## So what actually helps?

For a defender that is already competent and not capacity-starved — the state
most mature SOCs are in — **speed of detection is the highest-leverage
investment**, ahead of more sensors or more analysts. For a struggling,
alert-flooded SOC, fixing *how it triages and budgets attention* (the
HeuristicBlue→SOCBlue swap, and more capacity) comes first. Only the full
combination drives the attacker's win rate into the ground, but the order you
spend in should depend on which regime you're in — and this model lets you tell
which one that is.

## Caveats (read these)

- **Representative, not real.** A made-up network. Treat the *shape* of the
  conclusions as transferable, not the exact numbers.
- **Still an abstract model.** Detection is a probability per action, not real
  log analysis. Conclusions are about strategy and trade-offs.
- **Attacker is fixed.** All runs use the scripted Red; a different attacker
  could shift which levers matter. Re-run with `--red llm`/`rl` to probe that.

## Corrections (method integrity)

1. **A noise bug.** Hosts with no ENDPOINT sensor were still emitting
   endpoint-shaped *false alarms*, sending the defender chasing phantom threats
   on sensorless hosts. Fixed so look-alike noise only comes from sensors a host
   has (commit `4a92b20`). All numbers above are post-fix.
2. **A weak-defender artifact.** The first version of this report used only
   `HeuristicBlue` and concluded "analyst capacity is the bottleneck." Adding a
   competent `SOCBlue` showed that was specific to the weak defender; the honest
   conclusion is Findings 1–3 above.

## Adapting this to a real site

Edit `enterprise_network()` in `purple_sim/env/scenario.py` so the zones, hosts,
data location, and especially per-host sensor coverage and log latency match the
real architecture, then re-run `--analyze` with both `--blue heuristic` and
`--blue soc`. The model only needs shapes and relationships — no secrets,
credentials, or addresses.
