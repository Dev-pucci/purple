# Calibration — making the numbers mean something

**Status: the shipped defaults are illustrative, not validated.** Every
probability and duration in this model was chosen by hand to produce an
interesting, roughly-balanced game. They are good enough to study *relationships*
("faster logs matter more than more sensors") but you must **not** read an
absolute number ("Red wins 54%") as a prediction about any real environment
until the parameters below are calibrated to data and the outputs are checked
against reality. This file is the recipe for doing that; it does not itself
contain real-world figures, and none should be invented.

## How to inject calibrated values

Nothing here requires code changes. Every parameter is a config key or a
scenario field, so a calibrated model is just a config/scenario you supply:

- **Global parameters** → the `config` block of a `--scenario-file` JSON, or a
  `config=` dict passed to `Environment` (overrides `DEFAULT_CONFIG`).
- **Per-host / per-vulnerability** values → the `sensors` and `vulnerabilities`
  fields of each node in the scenario JSON.

Keep a calibrated profile under version control and cite its sources in the
file, so a reviewer can trace every number to where it came from.

## Parameter → source → method

"Source" names the *kind* of evidence that should set a parameter — your own
telemetry where you have it, otherwise published industry data. Fill the
"calibrated value" column yourself from sources you can cite; the method says
how to turn a published statistic into the parameter.

### Detection (the parameters the findings are most sensitive to)

| Parameter | What it means | Source | Method |
|---|---|---|---|
| per-host `sensors.NETWORK` / `.ENDPOINT` (0–1) | chance a visible action on that host is logged by that sensor | your EDR/NIDS deployment map + tool efficacy studies, detection-engineering coverage assessments (e.g. ATT&CK-technique coverage audits) | set coverage = fraction of relevant techniques that tooling on that host actually alerts on; 0 where a sensor is absent |
| `telemetry_latency` (min,max steps) | delay from action to Blue seeing the alert | your SIEM/alerting pipeline latency; IR reports' detection-time stats | measure your log→alert→triage delay and express it in turns (pick a turn = a fixed wall-clock unit for your site) |
| per-vuln `detection_prob` | base chance an attempt of that technique is logged (before sensor coverage) | detection-engineering test results, purple-team exercise logs, public technique-detection studies | = measured true-positive rate for that technique's detections |
| `log_retention` (steps) | how long an alert stays actionable in the analyst's view | your SOC's alert triage SLA / queue age | the age at which an un-triaged alert is effectively lost |

### Attacker success

| Parameter | What it means | Source | Method |
|---|---|---|---|
| per-vuln `success_prob` | chance an exploit/technique attempt lands | red-team / pentest success rates, exploitation-likelihood data (e.g. EPSS for the mapped CVE class), control-efficacy tests | = observed success rate of that technique against hosts in that role |
| `lateral_success` | chance a credentialed pivot takes | your segmentation + credential-hygiene posture; AD attack-path assessments | lower it as credential tiering / least-privilege improve |
| `escalate_fallback_success` | chance of the harder token-theft privesc when the main vuln is patched | privilege-escalation research, local-privesc prevalence | the residual success rate after patching the named privesc |
| `exfil_steps`, `exfil_detection` | turns to steal the data / per-turn detection | DLP efficacy, data-volume ÷ throttled channel; IR reports' exfiltration-time stats | size the window from realistic data volumes and your egress controls |

### Defender capacity and cost

| Parameter | What it means | Source | Method |
|---|---|---|---|
| `analyst_budget`, `analyst_costs` | action-points the SOC can spend per game and per action | your analyst headcount × shift hours ÷ mean handling time | scale to actions-per-incident-window your team can actually do |
| `investigate_boost` | detection lift from investigating a host | before/after detection rates when an analyst focuses a host | measured uplift |
| `restore_duration`, `patch_duration` | downtime of re-image / patch | your change-management / rebuild times | convert to turns |
| `noise_per_step`, `lookalike_prob` | false-positive volume / share that looks like an attack | your SIEM's benign-alert rate and its attack-shaped fraction | from alert-triage statistics |

### Topology

The network itself (zones, connections, which hosts hold data, where sensors
are) comes from your CMDB / architecture diagrams / asset inventory. Describe it
in a scenario JSON (see `scenarios/enterprise.json`); no secrets are needed,
only shapes, roles and coverage.

## Choosing the time unit

Many parameters are "in turns". Calibration requires fixing **one turn = one
wall-clock unit** (say, one hour) for your site, then expressing every duration
(latency, retention, durations, exfil window) in that unit consistently. State
the unit in the profile.

## Validation — the part that can't be skipped

Calibrated inputs are necessary but not sufficient. Before any output is quoted
as a prediction:

1. **Backtest** against incidents you have ground truth for — did the model's
   coverage/time-to-detect match what actually happened?
2. **Sensitivity-check** every headline conclusion: re-run with each uncertain
   parameter at the ends of its plausible range (`experiments.py` is built for
   this) and report the conclusion only where it survives.
3. **Have a domain expert review** the mechanics and the profile.

Until that is done, present results as *relative* and *illustrative* — which is
exactly how `ANALYSIS.md` is written.
