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

Reproduce (every table below comes from these):

```bash
python experiments.py                         # all three studies (defenders, posture, sensitivity)
python experiments.py --study sensitivity      # just the enterprise intervention sweep
python run.py --analyze --scenario enterprise --episodes 400 --quiet --blue soc  # blind-spot map
```

> Numbers are from ~200–400-game runs and move a few points run to run; the
> *relationships* are the findings, not the exact figures.

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

| Defender | Red win % | Blue score | coverage % |
|---|---|---|---|
| HeuristicBlue | 63 | −17 | 31 |
| SOCBlue | **54** | −38 | 29 |

Swapping to a budget-disciplined analyst — no new sensors, no bigger budget —
drops Red's win rate without touching the architecture. **Who is operating the
controls changes the result**, and any claim about "which control to buy" is
downstream of this. Note the tension: on this 9-host site under the default
analyst budget, `SOCBlue` wins more games but spends more doing it (a more
negative Blue score from extra downtime/false positives) — a symptom of being
under-resourced for the site's size, which Finding 2 picks apart.

## Finding 2 — the top lever depends on the defender

Each row changes one thing from the baseline and re-runs 300 games. "workstn %"
is mean coverage across the two (EDR-less) workstations.

**HeuristicBlue (reacts to the hottest host, wastes budget on noise):**

| Intervention | Red win % | coverage % | workstn % |
|---|---|---|---|
| baseline | 63 | 31 | 4 |
| + EDR on workstations | 65 | 31 | 6 |
| faster logs (latency 1) | 63 | 32 | 6 |
| **bigger SOC (budget 80)** | **41** | 36 | 13 |
| everything combined | 13 | 42 | 33 |

**SOCBlue (recency/severity, correlation, budget-disciplined):**

| Intervention | Red win % | coverage % | workstn % |
|---|---|---|---|
| baseline | 54 | 29 | 10 |
| + EDR on workstations | 55 | 30 | **15** |
| **faster logs (latency 1)** | **8** | 39 | 10 |
| bigger SOC (budget 80) | 54 | 29 | 10 |
| everything combined | 6 | 44 | 27 |

For the weak defender the binding constraint is **analyst capacity** (it burns
its budget chasing noise, so a bigger budget helps most: 63→41) while faster
logs do nothing (63→63) — it can't act on the signal it already has. For the
competent defender it is the mirror image: a bigger budget does **nothing**
(54→54, never capacity-starved) and the decisive lever is **log latency**,
which collapses Red's win rate from 54% to 8%. Same network, opposite advice,
depending on how good your SOC already is.

## Finding 3 — sensors buy visibility, not necessarily outcomes

Adding EDR to the blind workstations, with the competent defender, raised
**workstation coverage from 10% to 15%** — it genuinely sees more. But the win
rate didn't move (54→55), because those workstations aren't on the critical
path to the crown jewel. Visibility where the attacker isn't going improves
your coverage metric without improving the outcome. **Sensor placement relative
to the attack path matters more than sensor count.**

## Finding 4 — the latency result holds against a *learned* attacker

The findings above use the scripted Red. Re-running with a trained MaskablePPO
Red (200 games, default network) confirmed they aren't an artifact of a
hand-coded attacker — against `SOCBlue`, faster logs took the *learned* Red's
win rate from ~35% to ~6%, the same collapse as for the scripted Red, and the
smart defender exploited the faster signal far better than the weak one.

> Measured on an earlier trained Red; the action set has since changed (stealth
> variants were added), so that exact model no longer loads. Re-confirm after a
> fresh `train_rl.py --side red` run. The scripted-Red result (Finding 2) is the
> primary evidence; this was the cross-check.

## So what actually helps?

For a defender that is already competent and not capacity-starved — the state
most mature SOCs are in — **speed of detection is the highest-leverage
investment**, ahead of more sensors or more analysts. For a struggling,
alert-flooded SOC, fixing *how it triages and budgets attention* (the
HeuristicBlue→SOCBlue swap, and more capacity) comes first. Only the full
combination drives the attacker's win rate into the ground, but the order you
spend in should depend on which regime you're in — and this model lets you tell
which one that is.

## Finding 6 — the right tools beat more of the same

A third defender, `AdaptiveBlue`, adds two targeted capabilities to SOCBlue: a
**canary on the crown jewel** (a reliable tripwire regardless of sensor
coverage) and **credential rotation** on an identity host under attack (revoking
any domain-admin reach). On enterprise (300 games each):

| Defender | Red win % [95% CI] | Blue score | coverage % |
|---|---|---|---|
| heuristic | 63% [57, 68] | −17 | 31 |
| soc | 56% [50, 62] | −40 | 29 |
| **adaptive** | **22% [18, 27]** | **−6** | **42** |

Two cheap, well-placed controls — a tripwire on the asset that matters and
hygiene on the identity tier — cut the attacker's success by two-thirds and
*improved* availability (least-negative Blue score), far outperforming both
better triage (soc) and the generic sensor/budget levers of Finding 2.
**Placement and control *type* dominate control *volume*.** (The soc-vs-heuristic
gap, by contrast, is within the error bars here — a reminder to read the CIs.)

## Finding 5 — architecture matters as much as the defender

The same competent defender (`SOCBlue`) on two postures (300 games each):

| Network | Red win % |
|---|---|
| `enterprise` (segmented, EDR on key hosts) | 54 |
| `flat` (one LAN, DB among the workstations, sparse EDR) | 92 |

Segmentation plus sensor coverage cuts the attacker's success from near-certain
to a coin-flip — the same analyst, a very different outcome. Picking the
archetype (`--scenario enterprise` vs `flat`) closest to a real site, then
editing it, is the fastest way to see which structural weakness costs the most.

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
