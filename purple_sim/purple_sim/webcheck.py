"""webcheck — a defensive HTTP security-header / cookie analyzer.

Give it the *response headers* you already have (paste `curl -sI https://...`
output, or save a response and pass --file); it flags missing or weak security
controls with a rationale and a fix. It makes **no network connections** and
does not scan anything — it only reads headers you provide, so it is safe to run
against records for systems you don't operate.

  curl -sI https://example.com | python -m purple_sim.webcheck
  python -m purple_sim.webcheck --file headers.txt
  python -m purple_sim.webcheck --file headers.txt --json

This is a hygiene checklist, not a vulnerability scanner: a clean report means
the common headers are present and sane, not that the app is secure.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional

HIGH, MEDIUM, LOW, INFO = "high", "medium", "low", "info"
_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}


@dataclass
class Finding:
    severity: str
    header: str
    issue: str
    fix: str


def parse_headers(text: str) -> Dict[str, List[str]]:
    """Parse raw HTTP response headers. Keys are lower-cased; repeated headers
    (notably Set-Cookie) keep all values. The status line is ignored."""
    headers: Dict[str, List[str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or ":" not in line or line.upper().startswith("HTTP/"):
            continue
        name, _, value = line.partition(":")
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    return headers


def _first(headers: Dict[str, List[str]], name: str) -> Optional[str]:
    vals = headers.get(name)
    return vals[0] if vals else None


def analyze(headers: Dict[str, List[str]]) -> List[Finding]:
    f: List[Finding] = []

    def missing(name, sev, issue, fix):
        if name not in headers:
            f.append(Finding(sev, name, issue, fix))
            return True
        return False

    # Transport security
    hsts = _first(headers, "strict-transport-security")
    if hsts is None:
        f.append(Finding(HIGH, "Strict-Transport-Security",
                         "No HSTS: a downgrade/MITM can serve the site over HTTP.",
                         "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."))
    elif "max-age=0" in hsts.replace(" ", "") or "max-age" not in hsts:
        f.append(Finding(MEDIUM, "Strict-Transport-Security",
                         f"HSTS present but weak/disabled ({hsts!r}).",
                         "Use a long max-age (>= 15552000) and includeSubDomains."))

    # Content Security Policy
    csp = _first(headers, "content-security-policy")
    if csp is None:
        f.append(Finding(HIGH, "Content-Security-Policy",
                         "No CSP: no defence-in-depth against injected/3rd-party scripts (XSS).",
                         "Add a CSP starting from 'default-src \\'self\\'' and tighten from there."))
    else:
        flat = csp.replace(" ", "").lower()
        if "unsafe-inline" in flat or "unsafe-eval" in flat:
            f.append(Finding(MEDIUM, "Content-Security-Policy",
                             "CSP allows 'unsafe-inline'/'unsafe-eval', which largely defeats it.",
                             "Remove unsafe-* and use nonces/hashes for inline scripts."))
        if "default-src" not in flat and "script-src" not in flat:
            f.append(Finding(LOW, "Content-Security-Policy",
                             "CSP sets neither default-src nor script-src.",
                             "Set a restrictive default-src (e.g. 'self')."))

    missing("x-content-type-options", MEDIUM,
            "Missing: browsers may MIME-sniff responses into executable types.",
            "Add 'X-Content-Type-Options: nosniff'.")
    if "content-security-policy" not in headers and "x-frame-options" not in headers:
        f.append(Finding(MEDIUM, "X-Frame-Options",
                         "No clickjacking protection (no X-Frame-Options and no CSP frame-ancestors).",
                         "Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors \\'none\\''."))
    missing("referrer-policy", LOW,
            "Missing: full URLs may leak to third parties via the Referer header.",
            "Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.")
    missing("permissions-policy", LOW,
            "Missing: powerful browser features aren't restricted.",
            "Add a 'Permissions-Policy' disabling unused features (camera=(), geolocation=(), ...).")

    # Information disclosure
    for name in ("server", "x-powered-by", "x-aspnet-version"):
        val = _first(headers, name)
        if val and any(ch.isdigit() for ch in val):
            f.append(Finding(LOW, name.title(),
                             f"Reveals software/version ({val!r}), aiding targeting.",
                             f"Suppress or genericise the {name} header."))

    # Cookies
    for cookie in headers.get("set-cookie", []):
        attrs = cookie.lower()
        cname = cookie.split("=", 1)[0].strip() or "cookie"
        if "secure" not in attrs:
            f.append(Finding(HIGH, "Set-Cookie",
                             f"Cookie {cname!r} lacks Secure: it can be sent over HTTP.",
                             "Add the Secure attribute."))
        if "httponly" not in attrs:
            f.append(Finding(MEDIUM, "Set-Cookie",
                             f"Cookie {cname!r} lacks HttpOnly: readable by JavaScript (XSS theft).",
                             "Add the HttpOnly attribute (unless JS must read it)."))
        if "samesite" not in attrs:
            f.append(Finding(MEDIUM, "Set-Cookie",
                             f"Cookie {cname!r} has no SameSite: weaker CSRF protection.",
                             "Add 'SameSite=Lax' (or Strict)."))

    f.sort(key=lambda x: _ORDER.get(x.severity, 9))
    return f


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--file", help="Read headers from this file instead of stdin.")
    p.add_argument("--json", action="store_true", help="Emit findings as JSON.")
    args = p.parse_args(argv)
    text = open(args.file, encoding="utf-8").read() if args.file else sys.stdin.read()
    if not text.strip():
        print("No headers provided. Pipe `curl -sI <url>` output or use --file.", file=sys.stderr)
        return 2
    findings = analyze(parse_headers(text))
    if args.json:
        print(json.dumps([asdict(x) for x in findings], indent=2))
        return 0
    if not findings:
        print("No issues found in the common security headers. (Hygiene only — not a full audit.)")
        return 0
    counts = {s: sum(1 for x in findings if x.severity == s) for s in (HIGH, MEDIUM, LOW)}
    print(f"{len(findings)} finding(s): "
          f"{counts[HIGH]} high, {counts[MEDIUM]} medium, {counts[LOW]} low\n")
    for x in findings:
        print(f"[{x.severity.upper():<6}] {x.header}")
        print(f"         {x.issue}")
        print(f"         fix: {x.fix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
