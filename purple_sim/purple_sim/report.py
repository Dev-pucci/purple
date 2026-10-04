"""Render analysis results as a self-contained HTML report — the shareable
"product" surface over the CLI engine. Zero dependencies: one HTML string with
inline CSS and SVG bars, theme-aware (light/dark) and responsive.

`build_report(...)` takes already-computed results (so it never runs games
itself) and returns HTML; `experiments.py --html PATH` wires it to a run.
"""
from __future__ import annotations

import datetime
import html
from typing import List, Sequence, Tuple

# A small, accessible, colour-blind-safe pair (blue = defender, red = attacker).
_BLUE, _RED, _MUTED = "#2563eb", "#dc2626", "#94a3b8"


def _bar(frac: float, color: str, label: str) -> str:
    pct = max(0.0, min(1.0, frac)) * 100
    return (f'<div class="barwrap"><div class="bar"><div class="fill" '
            f'style="width:{pct:.1f}%;background:{color}"></div></div>'
            f'<span class="val">{html.escape(label)}</span></div>')


def _defender_table(rows: Sequence[dict]) -> str:
    out = ['<table><thead><tr><th>Defender</th><th>Attacker win rate</th>'
           '<th>Blue score</th><th>Coverage</th></tr></thead><tbody>']
    for r in rows:
        out.append(
            f'<tr><td class="name">{html.escape(r["name"])}</td>'
            f'<td>{_bar(r["red_win"] / 100, _RED, r["red_win_label"])}</td>'
            f'<td class="num">{r["blue_score"]:+.0f}</td>'
            f'<td>{_bar(r["coverage"] / 100, _BLUE, f"{r['coverage']:.0f}%")}</td></tr>')
    out.append('</tbody></table>')
    return "".join(out)


def _blindspot_table(rows: Sequence[Tuple[str, int, int]]) -> str:
    out = ['<table><thead><tr><th>Host</th><th>Attack steps</th>'
           '<th>Caught &amp; answered</th></tr></thead><tbody>']
    for host, executed, detected in rows:
        frac = detected / executed if executed else 0.0
        flag = ' <span class="flag">blind spot</span>' if executed >= 5 and frac < 0.25 else ""
        out.append(
            f'<tr><td class="name">{html.escape(host)}{flag}</td>'
            f'<td class="num">{executed}</td>'
            f'<td>{_bar(frac, _BLUE if frac >= 0.25 else _RED, f"{frac*100:.0f}%")}</td></tr>')
    out.append('</tbody></table>')
    return "".join(out)


def build_report(title: str, scenario: str, defenders: Sequence[dict],
                 blindspots: Sequence[Tuple[str, int, int]], findings: Sequence[str],
                 episodes: int, standalone: bool = True) -> str:
    """Return the report HTML. `standalone=True` is a full document (for a file);
    `standalone=False` is content-only (title + style + body), for an Artifact
    whose host supplies the document skeleton."""
    inner = _inner(title, scenario, defenders, blindspots, findings, episodes)
    if not standalone:
        return inner
    return ('<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1, '
            'viewport-fit=cover">\n</head><body>\n' + inner + "\n</body></html>")


def _inner(title: str, scenario: str, defenders: Sequence[dict],
           blindspots: Sequence[Tuple[str, int, int]], findings: Sequence[str],
           episodes: int) -> str:
    today = datetime.date.today().isoformat()
    findings_html = "".join(f"<li>{html.escape(f)}</li>" for f in findings)
    return f"""<title>{html.escape(title)}</title>
<style>
  :root {{ color-scheme: light;
    --bg:#f8fafc; --card:#ffffff; --ink:#0f172a; --muted:#64748b; --line:#e2e8f0; --track:#e2e8f0; }}
  @media (prefers-color-scheme: dark) {{ :root:not([data-theme="light"]) {{
    --bg:#0b1120; --card:#111827; --ink:#e5e7eb; --muted:#94a3b8; --line:#1f2937;
    --track:#1f2937; color-scheme:dark; }} }}
  :root[data-theme="dark"] {{
    --bg:#0b1120; --card:#111827; --ink:#e5e7eb; --muted:#94a3b8; --line:#1f2937;
    --track:#1f2937; color-scheme:dark; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
    font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }}
  .wrap {{ max-width:900px; margin:0 auto; padding:32px 20px 64px; }}
  header p {{ color:var(--muted); margin:.25rem 0 0; }}
  .badge {{ display:inline-block; font-size:12px; color:var(--muted);
    border:1px solid var(--line); border-radius:999px; padding:2px 10px; margin-top:8px; }}
  section {{ background:var(--card); border:1px solid var(--line); border-radius:14px;
    padding:20px 22px; margin:22px 0; }}
  h1 {{ font-size:24px; margin:0; }} h2 {{ font-size:17px; margin:0 0 14px; }}
  table {{ width:100%; border-collapse:collapse; }}
  th,td {{ text-align:left; padding:9px 8px; border-bottom:1px solid var(--line);
    vertical-align:middle; font-size:14px; }}
  th {{ color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase;
    letter-spacing:.03em; }}
  td.name {{ font-weight:600; white-space:nowrap; }} td.num {{ font-variant-numeric:tabular-nums; }}
  .barwrap {{ display:flex; align-items:center; gap:10px; min-width:0; }}
  .bar {{ flex:1; min-width:70px; background:var(--track); border-radius:6px; height:10px;
    overflow:hidden; }}
  .fill {{ height:100%; border-radius:6px; }}
  .val {{ font-size:13px; font-weight:600; font-variant-numeric:tabular-nums;
    color:var(--ink); white-space:nowrap; }}
  .flag {{ font-size:11px; color:#fff; background:var(--muted); border-radius:4px;
    padding:1px 6px; margin-left:6px; }}
  ul.findings {{ margin:0; padding-left:20px; }} ul.findings li {{ margin:6px 0; }}
  footer {{ color:var(--muted); font-size:12px; margin-top:28px; }}
  footer b {{ color:var(--ink); }}
</style>
<div class="wrap">
<header>
  <h1>{html.escape(title)}</h1>
  <p>Detection-coverage assessment on the <b>{html.escape(scenario)}</b> model network.</p>
  <span class="badge">{episodes} games/row &middot; generated {today} &middot; illustrative model, not validated</span>
</header>

<section><h2>How defenders compare</h2>
  <p style="color:var(--muted);margin-top:0">Lower attacker win rate and higher Blue score are better.</p>
  {_defender_table(defenders)}
</section>

<section><h2>Where attacks go unanswered (blind-spot map)</h2>
  <p style="color:var(--muted);margin-top:0">Share of real attack steps on each host that were detected
  <em>and</em> responded to.</p>
  {_blindspot_table(blindspots)}
</section>

<section><h2>Key findings</h2>
  <ul class="findings">{findings_html}</ul>
</section>

<footer>
  Generated by <b>purple_sim</b>. Numbers are from a model with illustrative
  parameters and carry run-to-run variance; treat the relationships, not the
  exact figures, as the result, and calibrate + validate before acting
  (see CALIBRATION.md).
</footer>
</div>"""
