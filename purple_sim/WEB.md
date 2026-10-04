# Red teaming and blue teaming a web app (in the sim)

This is the web-application side of `purple_sim`: a way to play attacker (Red)
against defender (Blue) over a model of a web app and measure, honestly, which
attacks get caught and which defenses actually help.

**Read this first — what it is and is not.** It is an *abstract model* of web
attack paths and detection, in the same graph engine as the network sim. It has
**no real requests, payloads, or exploit code**, and it never touches a real
site. OWASP categories and techniques are labels on abstract weaknesses with
success/detection probabilities. It is useful for reasoning about *strategy and
coverage* — where attacks slip through, which controls move the outcome — not
for finding bugs in a real app. For a real app, do a code review (put the code
here) and run `webcheck` on its response headers; for live testing use a proper
pentest/DAST under authorization. Treat relationships, not exact numbers, as the
result, and see `CALIBRATION.md`.

## The web kill chain (Red)

Red works the same five verbs as the network sim, mapped to web moves:

| Verb | Web meaning |
|---|---|
| SCAN | fingerprint an endpoint: its weaknesses and what it talks to |
| EXPLOIT | use a known web weakness (injection, misconfig, broken access) to get a foothold |
| ESCALATE | gain higher privilege on a service (privesc, or token/credential theft when patched) |
| LATERAL_MOVE | pivot to another service; SSRF and stolen OAuth/session creds cross trust boundaries |
| EXFILTRATE | pull the data from the crown-jewel store (needs ADMIN there), over several turns |

Crossing into the `secure` segment (the data store / vault) needs ADMIN on the
pivot — the web analogue of "you need a valid session/token, not just reach".
Compromising the identity/OAuth service (an identity host) yields app-wide
credentials, like stealing the keys to every session.

## OWASP Top 10 -> red move -> blue control -> how the sim catches it

The mapping below is in `attack_catalog.OWASP_TO_TECHNIQUE`. "Detection" is how a
real such event would surface in the model's telemetry.

| OWASP (2021) | Red move | Blue control (sim action) | Detection in the model |
|---|---|---|---|
| A01 Broken Access Control | reach data/functions beyond role | enforce authz server-side (PATCH); canary privileged objects (DECOY) | ENDPOINT/app logs; a canary is a reliable tripwire |
| A02 Cryptographic Failures | harvest secrets/tokens | rotate secrets (ROTATE_CREDS); TLS/HSTS (`webcheck`) | ENDPOINT on the vault; rotation revokes stolen creds |
| A03 Injection | inject into a query/command | parameterise/patch (PATCH); WAF + logs (INVESTIGATE) | NETWORK (WAF) + ENDPOINT; WAF gives strong coverage |
| A04 Insecure Design | abuse a missing control | add the control (PATCH) — not fully patchable | weak unless a sensor/canary is placed |
| A05 Security Misconfiguration | exploit default/verbose surface | harden config (PATCH); suppress disclosure (`webcheck`) | NETWORK/ENDPOINT at the edge |
| A06 Vulnerable Components | exploit a known CVE | patch/upgrade (PATCH) | depends on sensor coverage of that host |
| A07 Auth Failures | bypass/steal auth; forge sessions | rotate sessions/keys (ROTATE_CREDS); MFA/lockout (PATCH) | ENDPOINT on the identity service |
| A08 Integrity Failures (web shell) | plant a web shell / tamper pipeline | re-deploy clean (RESTORE); integrity checks (PATCH) | PRIVESC/EXPLOIT telemetry; RESTORE evicts |
| A09 Logging & Monitoring Failures | operate under a blind spot | add logging/alerting (INVESTIGATE); cut latency/retention | *this is the absence of detection* — model it with low sensor coverage / high latency |
| A10 SSRF | pivot through the server to internal services | egress allow-listing / segment (ISOLATE/PATCH) | NETWORK (lateral) telemetry |

A09 is the important one: in this model "bad logging" is not an attack, it is
**low sensor coverage, high `telemetry_latency`, or short `log_retention`** — so
Finding 2 from `ANALYSIS.md` (for a competent defender, detection *speed* beats
more sensors) is really a statement about A09.

## Defenders to play

- `--blue heuristic` — reacts to the single hottest alert.
- `--blue soc` — recency/severity-weighted, correlates across services, budget-aware.
- `--blue adaptive` — soc plus canaries and credential rotation. **Note:** on the
  web scenarios this currently underperforms `soc` — its enterprise-tuned
  priorities (canary the DB, rotate the IdP) misfit the web topology. A real
  lesson: a defensive playbook tuned for one environment doesn't transfer blindly.

## Scenarios and how to run

- `webapp` — a monolith by trust layer (WAF-watched web tier -> API -> OAuth -> DB).
- `webapp_micro` — an API gateway fronting microservices, an OAuth service, a
  secrets vault and the DB (more east-west paths; harder to defend).

```bash
python run.py --scenario webapp --blue soc                       # watch a game
python run.py --analyze --scenario webapp_micro --blue soc       # blind-spot map
python experiments.py --scenario webapp --html web_report.html   # shareable report
```

Observation so far: the microservices posture is meaningfully harder for the
defender than the monolith (more services to pivot between, a vault of reusable
credentials) — the web analogue of Finding 5 (architecture is a top-tier control).
As always, calibrate and validate before reading the numbers as more than
relative.
