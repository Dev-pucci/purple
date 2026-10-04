# Detection-coverage analysis on a representative enterprise network

**What this is.** A worked analysis using `purple_sim` on the built-in
`enterprise` scenario — a *representative* multi-tier network, **not** any real
environment. The point is to show the kind of defensive insight the model
produces and which levers matter, in a form you can re-run after editing the
scenario to resemble your own site. Nothing here touches a real system.

Reproduce the headline map with:

```bash
python run.py --analyze --scenario enterprise --episodes 400 --quiet
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

Endpoint-sensor (EDR) coverage was set to a realistic, uneven pattern: strong
on the domain controller and database (0.9), medium on servers, **none on the
two workstations (0.0)**, weak on the file server (0.4). Network-sensor (NIDS)
coverage is 0.5–0.8 everywhere.

## Baseline blind-spot map (400 games, scripted vs scripted)

Red win rate **69%**. Coverage = share of real attack steps on that host /
technique that Blue both saw in telemetry *and* responded to.

| Host | coverage | | Technique | coverage |
|---|---|---|---|---|
| workstation_hr | **0%** | | T1078 Valid Accounts | **2%** |
| workstation_eng | **3%** | | T1048 Exfiltration | 25% |
| file_server | 22% | | T1190 Public-facing exploit | 28% |
| db_cluster | 30% | | T1021 Remote services | 30% |
| web_proxy / jump_host | ~30% | | T1068 Privilege escalation | 35% |
| domain_controller | 45% | | T1210 Remote services exploit | 36% |

The blind spots line up exactly with the sensor gaps: the EDR-less workstations
are near-invisible, and credential-based access to them (T1078) is essentially
never caught.

## Sensitivity study: which fix actually helps?

Each row changes one thing from the baseline and re-runs 300 games. "workstn %"
is mean coverage across the two workstations.

| Intervention | Red win % | coverage % | workstn % | T1078 % | file % |
|---|---|---|---|---|---|
| baseline | 69 | 30 | 1 | 1 | 24 |
| + EDR on workstations | 69 | 30 | 3 | 5 | 24 |
| + EDR on file_server | 69 | 30 | 1 | 2 | 33 |
| faster logs (latency 1) | 62 | 30 | 3 | 4 | 19 |
| bigger SOC (budget 80) | 47 | 35 | 14 | 9 | 27 |
| all endpoint sensors | 70 | 30 | 2 | 3 | 33 |
| **everything combined** | **13** | **41** | **32** | **36** | **42** |

## The finding

**Adding visibility you can't act on barely changes the outcome.** Giving the
workstations EDR on its own moved their coverage from 1% to 3% and did nothing
to the win rate — because the binding constraint in the baseline is the SOC's
*capacity and speed to respond*, not whether the event was recordable. The
single most effective one-change lever was **more analyst capacity** (Red
69%→47%), and only when sensors, log speed, and capacity were improved
*together* did the picture transform (Red 69%→**13%**, workstation coverage
1%→32%).

Detection is a pipeline — **see it, see it in time, have capacity to act** — and
lifting one stage while another is the bottleneck wastes the spend. That is the
kind of conclusion this model exists to make visible, and it is the opposite of
the usual instinct to buy more sensors first.

## Caveats (read these)

- **Representative, not real.** This is a made-up network. Treat the *shape* of
  the conclusions as transferable, not the exact numbers.
- **Depends on the defender.** "EDR alone doesn't help" is partly a property of
  the simple heuristic Blue, which doesn't aggressively prioritise fresh
  workstation alerts. A smarter Blue (or an LLM/RL one) might convert the extra
  visibility better. Re-run with a different Blue to test that.
- **Abstract model.** Detection is a probability per action, not real log
  analysis; "exploit" is a dice roll, not a technique. Conclusions are about
  strategy and trade-offs, not whether a specific control is configured right.

## Adapting this to a real site

Edit `enterprise_network()` in `purple_sim/env/scenario.py` so the zones, hosts,
data location, and especially the per-host sensor coverage match the real
architecture, then re-run `--analyze`. The model only needs shapes and
relationships — no secrets, credentials, or addresses.
