#!/usr/bin/env python3
"""
WebSec Scanner — All-in-one Flask Web UI
Run:  python app.py
Then open:  http://localhost:5000
"""

import sys
import re
import json
import base64
import requests
import urllib3
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

from flask import Flask, request, render_template_string

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ══════════════════════════════════════════════════════════════════════════════
# ENGINE
# ══════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT = 10
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; WebSecScanner/1.0)"
}
CORS_PROBE_ORIGINS = [
    "https://evil.com",
    "null",
    "https://attacker.example.com",
]


class ScanResult:
    def __init__(self, url: str):
        self.url = url
        self.final_url = url
        self.status_code: int = 0
        self.response_headers: dict = {}
        self.cors_probe_results: list = []
        self.scanned_at: str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        self.error: str | None = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "scanned_at": self.scanned_at,
            "response_headers": self.response_headers,
            "cors_probe_results": self.cors_probe_results,
            "error": self.error,
        }


def _fetch(url: str, origin: str | None = None, timeout: int = DEFAULT_TIMEOUT):
    headers = dict(DEFAULT_HEADERS)
    if origin:
        headers["Origin"] = origin
    return requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)


def scan(url: str, timeout: int = DEFAULT_TIMEOUT) -> ScanResult:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    result = ScanResult(url)
    try:
        resp = _fetch(url, timeout=timeout)
        result.final_url = resp.url
        result.status_code = resp.status_code
        result.response_headers = {k.lower(): v for k, v in resp.headers.items()}
    except requests.exceptions.RequestException as exc:
        result.error = str(exc)
        return result
    for origin in CORS_PROBE_ORIGINS:
        probe = {"probed_origin": origin, "acao": None, "acac": None, "acam": None, "error": None}
        try:
            r = _fetch(url, origin=origin, timeout=timeout)
            probe["acao"] = r.headers.get("Access-Control-Allow-Origin")
            probe["acac"] = r.headers.get("Access-Control-Allow-Credentials")
            probe["acam"] = r.headers.get("Access-Control-Allow-Methods")
        except requests.exceptions.RequestException as exc:
            probe["error"] = str(exc)
        result.cors_probe_results.append(probe)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# HEADERS AUDIT
# ══════════════════════════════════════════════════════════════════════════════

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"]


@dataclass
class HeaderFinding:
    header: str
    status: Severity
    value: str | None
    message: str
    recommendation: str


def _check_csp(value):
    header = "content-security-policy"
    if value is None:
        return HeaderFinding(header=header, status="HIGH", value=None,
            message="Content-Security-Policy header is missing.",
            recommendation="Define a strict CSP to mitigate XSS. Example: default-src 'self'; script-src 'self'.")
    issues = []
    lower = value.lower()
    if "unsafe-inline" in lower: issues.append("'unsafe-inline' allows inline scripts (XSS risk)")
    if "unsafe-eval" in lower:   issues.append("'unsafe-eval' allows eval() (XSS risk)")
    if "*" in value and "default-src" in lower: issues.append("wildcard (*) in default-src is overly permissive")
    if issues:
        return HeaderFinding(header=header, status="MEDIUM", value=value,
            message="CSP present but contains weak directives: " + "; ".join(issues),
            recommendation="Remove 'unsafe-inline', 'unsafe-eval', and wildcard sources.")
    return HeaderFinding(header=header, status="PASS", value=value,
        message="CSP is present and looks reasonable.", recommendation="")


def _check_hsts(value):
    header = "strict-transport-security"
    if value is None:
        return HeaderFinding(header=header, status="HIGH", value=None,
            message="Strict-Transport-Security (HSTS) header is missing.",
            recommendation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload")
    lower = value.lower()
    issues = []
    match = re.search(r"max-age=(\d+)", lower)
    if match:
        if int(match.group(1)) < 31536000: issues.append("max-age is less than 1 year")
    else:
        issues.append("max-age directive is missing")
    if "includesubdomains" not in lower: issues.append("includeSubDomains is missing")
    if issues:
        return HeaderFinding(header=header, status="MEDIUM", value=value,
            message="HSTS present but weak: " + "; ".join(issues),
            recommendation="Use: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload")
    return HeaderFinding(header=header, status="PASS", value=value,
        message="HSTS is properly configured.", recommendation="")


def _check_x_frame(value):
    header = "x-frame-options"
    if value is None:
        return HeaderFinding(header=header, status="HIGH", value=None,
            message="X-Frame-Options header is missing — site may be vulnerable to Clickjacking.",
            recommendation="Add: X-Frame-Options: DENY  (or SAMEORIGIN if framing on same origin is needed).")
    if value.upper() not in ("DENY", "SAMEORIGIN"):
        return HeaderFinding(header=header, status="MEDIUM", value=value,
            message=f"X-Frame-Options value '{value}' is non-standard.",
            recommendation="Use DENY or SAMEORIGIN.")
    return HeaderFinding(header=header, status="PASS", value=value,
        message="X-Frame-Options is properly set.", recommendation="")


def _check_x_content_type(value):
    header = "x-content-type-options"
    if value is None:
        return HeaderFinding(header=header, status="MEDIUM", value=None,
            message="X-Content-Type-Options header is missing — MIME sniffing attacks possible.",
            recommendation="Add: X-Content-Type-Options: nosniff")
    if value.lower() != "nosniff":
        return HeaderFinding(header=header, status="MEDIUM", value=value,
            message=f"Unexpected value '{value}' — should be 'nosniff'.",
            recommendation="Set X-Content-Type-Options: nosniff")
    return HeaderFinding(header=header, status="PASS", value=value,
        message="X-Content-Type-Options is correctly set to nosniff.", recommendation="")


def _check_referrer_policy(value):
    header = "referrer-policy"
    safe = {"no-referrer","no-referrer-when-downgrade","strict-origin","strict-origin-when-cross-origin"}
    if value is None:
        return HeaderFinding(header=header, status="LOW", value=None,
            message="Referrer-Policy header is missing — full URL may leak in Referer header.",
            recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin")
    if value.lower() not in safe:
        return HeaderFinding(header=header, status="LOW", value=value,
            message=f"Referrer-Policy value '{value}' may leak sensitive URL information.",
            recommendation="Use: strict-origin-when-cross-origin or no-referrer.")
    return HeaderFinding(header=header, status="PASS", value=value,
        message="Referrer-Policy is properly configured.", recommendation="")


def _check_permissions_policy(value):
    header = "permissions-policy"
    if value is None:
        return HeaderFinding(header=header, status="LOW", value=None,
            message="Permissions-Policy header is missing — browser features are unrestricted.",
            recommendation="Add a Permissions-Policy header to restrict camera, microphone, geolocation, etc.")
    return HeaderFinding(header=header, status="PASS", value=value,
        message="Permissions-Policy header is present.", recommendation="")


def _check_x_xss_protection(value):
    header = "x-xss-protection"
    if value is None:
        return HeaderFinding(header=header, status="INFO", value=None,
            message="X-XSS-Protection header is absent (acceptable for modern browsers).",
            recommendation="Optionally set to '0' to disable the buggy IE XSS filter, or rely on CSP instead.")
    if value.strip() == "0":
        return HeaderFinding(header=header, status="INFO", value=value,
            message="X-XSS-Protection: 0 — XSS filter explicitly disabled (modern best practice).",
            recommendation="Ensure a strong CSP is in place.")
    return HeaderFinding(header=header, status="PASS", value=value,
        message="X-XSS-Protection is set.", recommendation="")


def _check_server_leakage(value):
    header = "server"
    if value is None:
        return HeaderFinding(header=header, status="PASS", value=None,
            message="Server header is absent — good, no technology info leaked.", recommendation="")
    if re.search(r"[\d.]{3,}", value):
        return HeaderFinding(header=header, status="MEDIUM", value=value,
            message=f"Server header reveals version info: '{value}' — aids fingerprinting.",
            recommendation="Strip or genericise the Server header in your web server config.")
    return HeaderFinding(header=header, status="LOW", value=value,
        message=f"Server header reveals technology: '{value}'.",
        recommendation="Consider removing or generalising the Server header.")


def _check_x_powered_by(value):
    header = "x-powered-by"
    if value is None:
        return HeaderFinding(header=header, status="PASS", value=None,
            message="X-Powered-By header is absent — good.", recommendation="")
    return HeaderFinding(header=header, status="MEDIUM", value=value,
        message=f"X-Powered-By reveals framework info: '{value}'.",
        recommendation="Remove X-Powered-By header (e.g. app.disable('x-powered-by') in Express).")


HEADER_CHECKS = [
    ("content-security-policy",   _check_csp),
    ("strict-transport-security", _check_hsts),
    ("x-frame-options",           _check_x_frame),
    ("x-content-type-options",    _check_x_content_type),
    ("referrer-policy",           _check_referrer_policy),
    ("permissions-policy",        _check_permissions_policy),
    ("x-xss-protection",          _check_x_xss_protection),
    ("server",                    _check_server_leakage),
    ("x-powered-by",              _check_x_powered_by),
]


def audit_headers(response_headers: dict) -> list:
    return [check_fn(response_headers.get(name)) for name, check_fn in HEADER_CHECKS]


# ══════════════════════════════════════════════════════════════════════════════
# CORS AUDIT
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class CORSFinding:
    probed_origin: str
    acao: str | None
    acac: str | None
    acam: str | None
    status: Severity
    title: str
    description: str
    recommendation: str


def _classify_cors(probe: dict) -> CORSFinding:
    origin = probe["probed_origin"]
    acao   = probe.get("acao")
    acac   = (probe.get("acac") or "").lower().strip()
    acam   = probe.get("acam")
    creds  = acac == "true"

    if origin == "null" and acao == "null":
        if creds:
            return CORSFinding(origin, acao, probe.get("acac"), acam, "CRITICAL",
                "CORS: null origin reflected with credentials",
                "Server reflects 'null' origin with credentials enabled — sandboxed iframes can steal authenticated data.",
                "Never trust the 'null' origin. Use an explicit trusted origin allowlist.")
        return CORSFinding(origin, acao, probe.get("acac"), acam, "HIGH",
            "CORS: null origin accepted",
            "Server allows the 'null' origin — sandboxed iframes can bypass same-origin policy.",
            "Do not allow the 'null' origin. Use an explicit trusted origin allowlist.")

    if acao == origin:
        if creds:
            return CORSFinding(origin, acao, probe.get("acac"), acam, "CRITICAL",
                "CORS: Arbitrary origin reflected with credentials enabled",
                f"Server reflects attacker-controlled origin '{origin}' with credentials — critical CORS misconfiguration.",
                "Validate Origin against a strict server-side allowlist. Never reflect arbitrary origins.")
        return CORSFinding(origin, acao, probe.get("acac"), acam, "HIGH",
            "CORS: Arbitrary origin reflected (no credentials)",
            f"Server reflects '{origin}' — attacker can read cross-origin responses.",
            "Validate Origin against a strict allowlist. Do not reflect arbitrary origins.")

    if acao == "*":
        if creds:
            return CORSFinding(origin, acao, probe.get("acac"), acam, "HIGH",
                "CORS: Wildcard origin with credentials (misconfigured)",
                "ACAO is '*' with ACAC 'true' — browsers reject this but it signals a fundamental misconfiguration.",
                "Never pair ACAO: * with ACAC: true. Use an explicit origin allowlist.")
        return CORSFinding(origin, acao, probe.get("acac"), acam, "MEDIUM",
            "CORS: Wildcard origin allowed",
            "ACAO is '*' — any origin can read responses. Dangerous for APIs returning sensitive data.",
            "For authenticated or sensitive endpoints, use an explicit origin allowlist.")

    return CORSFinding(origin, acao, probe.get("acac"), acam, "PASS",
        "CORS: Origin correctly rejected",
        f"No ACAO header returned for origin '{origin}'.", "")


def audit_cors(cors_probe_results: list) -> list:
    findings = []
    for probe in cors_probe_results:
        if probe.get("error"):
            findings.append(CORSFinding(probe["probed_origin"], None, None, None, "INFO",
                "CORS probe failed", f"Probe failed: {probe['error']}", "Ensure the target is reachable."))
        else:
            findings.append(_classify_cors(probe))
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# REPORTER
# ══════════════════════════════════════════════════════════════════════════════

SEVERITY_COLORS = {
    "CRITICAL": "#ff2d55", "HIGH": "#ff6b35", "MEDIUM": "#ffd60a",
    "LOW": "#30d158", "INFO": "#64d2ff", "PASS": "#32d74b",
}
SEVERITY_BG = {
    "CRITICAL": "rgba(255,45,85,0.18)", "HIGH": "rgba(255,107,53,0.18)",
    "MEDIUM": "rgba(255,214,10,0.15)", "LOW": "rgba(48,209,88,0.12)",
    "INFO": "rgba(100,210,255,0.12)", "PASS": "rgba(50,215,75,0.10)",
}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"]


def _badge(sev):
    c, bg = SEVERITY_COLORS.get(sev, "#aaa"), SEVERITY_BG.get(sev, "rgba(255,255,255,0.1)")
    return (f'<span style="display:inline-block;padding:2px 10px;border-radius:12px;'
            f'font-size:0.75rem;font-weight:700;letter-spacing:0.08em;'
            f'color:{c};background:{bg};border:1px solid {c};">{sev}</span>')


def _score_summary(hf, cf):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in hf: counts[f.status] += 1
    for f in cf: counts[f.status] += 1
    return counts


def _overall_grade(counts):
    if counts["CRITICAL"] > 0: return "F", SEVERITY_COLORS["CRITICAL"]
    if counts["HIGH"] > 0:     return "D", SEVERITY_COLORS["HIGH"]
    if counts["MEDIUM"] > 0:   return "C", SEVERITY_COLORS["MEDIUM"]
    if counts["LOW"] > 0:      return "B", SEVERITY_COLORS["LOW"]
    return "A", SEVERITY_COLORS["PASS"]


def _header_rows(findings):
    rows = []
    for f in findings:
        bg = SEVERITY_BG.get(f.status, "transparent")
        val = (f'<code style="font-size:0.78rem;color:#c9d1d9;word-break:break-all;">{f.value}</code>'
               if f.value else '<span style="color:#555;font-style:italic;">absent</span>')
        rec = (f'<span style="color:#8b949e;font-size:0.78rem;">{f.recommendation}</span>'
               if f.recommendation else '<span style="color:#32d74b;font-size:0.78rem;">No action needed</span>')
        rows.append(f'<tr style="background:{bg};border-bottom:1px solid rgba(255,255,255,0.06);">'
                    f'<td style="padding:10px 14px;font-weight:600;color:#e6edf3;">{f.header}</td>'
                    f'<td style="padding:10px 14px;">{_badge(f.status)}</td>'
                    f'<td style="padding:10px 14px;">{val}</td>'
                    f'<td style="padding:10px 14px;color:#c9d1d9;font-size:0.82rem;">{f.message}</td>'
                    f'<td style="padding:10px 14px;">{rec}</td></tr>')
    return "\n".join(rows)


def _cors_cards(findings):
    cards = []
    for f in findings:
        bc = SEVERITY_COLORS.get(f.status, "#444")
        bg = SEVERITY_BG.get(f.status, "transparent")
        acao_v = f.acao or '<span style="color:#555;font-style:italic;">not set</span>'
        acac_v = f.acac or '<span style="color:#555;font-style:italic;">not set</span>'
        rec = (f'<div style="margin-top:8px;padding:8px 12px;background:rgba(0,0,0,0.3);'
               f'border-left:3px solid {bc};border-radius:4px;font-size:0.82rem;color:#8b949e;">'
               f'<strong style="color:#c9d1d9;">Recommendation:</strong> {f.recommendation}</div>'
               if f.recommendation else "")
        cards.append(
            f'<div style="background:{bg};border:1px solid {bc};border-radius:10px;padding:18px 20px;margin-bottom:14px;">'
            f'<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;">{_badge(f.status)}'
            f'<span style="font-weight:700;color:#e6edf3;">{f.title}</span></div>'
            f'<p style="margin:0 0 10px;color:#c9d1d9;font-size:0.85rem;">{f.description}</p>'
            f'<div style="font-size:0.78rem;color:#8b949e;">'
            f'<strong style="color:#c9d1d9;">Probed origin:</strong> <code style="color:#79c0ff;">{f.probed_origin}</code> &nbsp;'
            f'<strong style="color:#c9d1d9;">ACAO:</strong> <code style="color:#ffa657;">{acao_v}</code> &nbsp;'
            f'<strong style="color:#c9d1d9;">ACAC:</strong> <code style="color:#ffa657;">{acac_v}</code></div>'
            f'{rec}</div>')
    return "\n".join(cards)


def _stat_pill(label, value, sev):
    c, bg = SEVERITY_COLORS.get(sev, "#aaa"), SEVERITY_BG.get(sev, "rgba(255,255,255,0.1)")
    return (f'<div style="display:flex;flex-direction:column;align-items:center;padding:14px 22px;'
            f'background:{bg};border:1px solid {c};border-radius:12px;min-width:80px;">'
            f'<span style="font-size:1.9rem;font-weight:800;color:{c};">{value}</span>'
            f'<span style="font-size:0.72rem;color:{c};letter-spacing:0.1em;margin-top:2px;">{label}</span></div>')


def build_report_html(result, header_findings, cors_findings, back_button=False):
    counts = _score_summary(header_findings, cors_findings)
    grade, gc = _overall_grade(counts)
    pills = "".join(_stat_pill(s, counts[s], s) for s in SEVERITY_ORDER if s not in ("PASS","INFO") or counts[s] > 0)
    back = ('<div style="max-width:1100px;margin:0 auto;padding:20px 20px 0;">'
            '<a href="/" style="display:inline-block;padding:8px 20px;background:#238636;'
            'border-radius:8px;color:#fff;text-decoration:none;font-weight:700;font-size:0.85rem;">'
            '&#8592; Scan Another URL</a></div>' if back_button else "")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>WebSec Scanner Report</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,"Segoe UI",system-ui,sans-serif;color:#c9d1d9;min-height:100vh;
          background:#000 radial-gradient(ellipse at 20% 50%, rgba(30,0,80,0.7) 0%, transparent 60%),
                     radial-gradient(ellipse at 80% 20%, rgba(0,40,100,0.6) 0%, transparent 55%),
                     radial-gradient(ellipse at 60% 80%, rgba(60,0,60,0.5) 0%, transparent 50%),
                     #050510;}}
    body::before{{content:'';position:fixed;inset:0;pointer-events:none;
      background-image:
        radial-gradient(1px 1px at 10% 15%, #fff 0%, transparent 100%),
        radial-gradient(1px 1px at 25% 40%, rgba(255,255,255,0.8) 0%, transparent 100%),
        radial-gradient(1.5px 1.5px at 40% 10%, #fff 0%, transparent 100%),
        radial-gradient(1px 1px at 55% 60%, rgba(255,255,255,0.6) 0%, transparent 100%),
        radial-gradient(1px 1px at 70% 25%, #fff 0%, transparent 100%),
        radial-gradient(1.5px 1.5px at 80% 70%, rgba(255,255,255,0.9) 0%, transparent 100%),
        radial-gradient(1px 1px at 90% 45%, rgba(255,255,255,0.7) 0%, transparent 100%),
        radial-gradient(1px 1px at 15% 75%, #fff 0%, transparent 100%),
        radial-gradient(1px 1px at 35% 85%, rgba(255,255,255,0.5) 0%, transparent 100%),
        radial-gradient(1px 1px at 60% 35%, rgba(200,200,255,0.8) 0%, transparent 100%),
        radial-gradient(1px 1px at 75% 90%, rgba(255,255,255,0.6) 0%, transparent 100%),
        radial-gradient(1px 1px at 5%  50%, rgba(255,255,255,0.4) 0%, transparent 100%),
        radial-gradient(1px 1px at 45% 55%, rgba(200,220,255,0.7) 0%, transparent 100%),
        radial-gradient(1px 1px at 88% 12%, rgba(255,255,255,0.9) 0%, transparent 100%),
        radial-gradient(1px 1px at 20% 95%, rgba(255,255,255,0.5) 0%, transparent 100%),
        radial-gradient(1.5px 1.5px at 50% 80%, rgba(180,180,255,0.8) 0%, transparent 100%),
        radial-gradient(1px 1px at 65% 5%,  rgba(255,255,255,0.6) 0%, transparent 100%),
        radial-gradient(1px 1px at 95% 65%, rgba(255,255,255,0.4) 0%, transparent 100%),
        radial-gradient(1px 1px at 30% 20%, rgba(200,200,255,0.7) 0%, transparent 100%),
        radial-gradient(1px 1px at 85% 35%, rgba(255,255,255,0.5) 0%, transparent 100%);}}
    .overlay{{min-height:100vh;background:rgba(4,8,18,0.75);padding:40px 20px;}}
    .container{{max-width:1100px;margin:0 auto;}}
    .banner{{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px;
             background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);border-radius:14px;
             padding:24px 30px;margin-bottom:28px;}}
    .banner h1{{font-size:1.6rem;font-weight:800;color:#e6edf3;}} .banner h1 span{{color:#58a6ff;}}
    .banner p{{font-size:0.82rem;color:#8b949e;margin-top:4px;}}
    .grade{{display:flex;flex-direction:column;align-items:center;background:rgba(0,0,0,0.4);
            border:2px solid {gc};border-radius:14px;padding:10px 24px;}}
    .grade .letter{{font-size:3rem;font-weight:900;color:{gc};line-height:1;}}
    .grade .label{{font-size:0.65rem;color:{gc};letter-spacing:0.12em;margin-top:4px;}}
    .info-card{{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:12px;
                padding:20px 24px;margin-bottom:22px;display:flex;flex-wrap:wrap;gap:20px;}}
    .info-item{{display:flex;flex-direction:column;gap:3px;}}
    .info-item .key{{font-size:0.68rem;color:#8b949e;letter-spacing:0.1em;text-transform:uppercase;}}
    .info-item .val{{font-size:0.88rem;color:#e6edf3;font-weight:600;word-break:break-all;}}
    .stats-row{{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:28px;}}
    .section{{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:14px;
              padding:24px 26px;margin-bottom:24px;}}
    .section h2{{font-size:1.1rem;font-weight:700;color:#e6edf3;margin-bottom:18px;}}
    table{{width:100%;border-collapse:collapse;font-size:0.83rem;}}
    thead th{{text-align:left;padding:10px 14px;font-size:0.7rem;text-transform:uppercase;
              letter-spacing:0.1em;color:#8b949e;border-bottom:1px solid rgba(255,255,255,0.1);}}
    tbody tr:hover{{background:rgba(255,255,255,0.04)!important;}}
  </style>
</head>
<body><div class="overlay">
{back}
<div class="container">
  <div class="banner">
    <div><h1>&#x1F6E1; <span>WebSec</span> Scanner</h1><p>Security Headers &amp; CORS Audit Report</p></div>
    <div class="grade"><span class="letter">{grade}</span><span class="label">SECURITY GRADE</span></div>
  </div>
  <div class="info-card">
    <div class="info-item"><span class="key">Target URL</span><span class="val">{result.url}</span></div>
    <div class="info-item"><span class="key">Final URL</span><span class="val">{result.final_url}</span></div>
    <div class="info-item"><span class="key">HTTP Status</span><span class="val">{result.status_code}</span></div>
    <div class="info-item"><span class="key">Scanned At</span><span class="val">{result.scanned_at}</span></div>
  </div>
  <div class="stats-row">{pills}</div>
  <div class="section">
    <h2>Security Headers Audit</h2>
    <div style="overflow-x:auto;"><table>
      <thead><tr><th>Header</th><th>Status</th><th>Current Value</th><th>Finding</th><th>Recommendation</th></tr></thead>
      <tbody>{_header_rows(header_findings)}</tbody>
    </table></div>
  </div>
  <div class="section"><h2>CORS Flaw Analysis</h2>{_cors_cards(cors_findings)}</div>
</div></div></body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
# FLASK WEB APP
# ══════════════════════════════════════════════════════════════════════════════

app = Flask(__name__)

HOME_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>WebSec Scanner</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,"Segoe UI",system-ui,sans-serif;color:#c9d1d9;
         min-height:100vh;display:flex;align-items:center;justify-content:center;
         background:#000 radial-gradient(ellipse at 20% 50%, rgba(30,0,80,0.7) 0%, transparent 60%),
                    radial-gradient(ellipse at 80% 20%, rgba(0,40,100,0.6) 0%, transparent 55%),
                    radial-gradient(ellipse at 60% 80%, rgba(60,0,60,0.5) 0%, transparent 50%),
                    #050510;}
    body::before{content:'';position:fixed;inset:0;pointer-events:none;
      background-image:
        radial-gradient(1px 1px at 10% 15%, #fff 0%, transparent 100%),
        radial-gradient(1px 1px at 25% 40%, rgba(255,255,255,0.8) 0%, transparent 100%),
        radial-gradient(1.5px 1.5px at 40% 10%, #fff 0%, transparent 100%),
        radial-gradient(1px 1px at 55% 60%, rgba(255,255,255,0.6) 0%, transparent 100%),
        radial-gradient(1px 1px at 70% 25%, #fff 0%, transparent 100%),
        radial-gradient(1.5px 1.5px at 80% 70%, rgba(255,255,255,0.9) 0%, transparent 100%),
        radial-gradient(1px 1px at 90% 45%, rgba(255,255,255,0.7) 0%, transparent 100%),
        radial-gradient(1px 1px at 15% 75%, #fff 0%, transparent 100%),
        radial-gradient(1px 1px at 35% 85%, rgba(255,255,255,0.5) 0%, transparent 100%),
        radial-gradient(1px 1px at 60% 35%, rgba(200,200,255,0.8) 0%, transparent 100%),
        radial-gradient(1px 1px at 75% 90%, rgba(255,255,255,0.6) 0%, transparent 100%),
        radial-gradient(1px 1px at 5%  50%, rgba(255,255,255,0.4) 0%, transparent 100%),
        radial-gradient(1px 1px at 45% 55%, rgba(200,220,255,0.7) 0%, transparent 100%),
        radial-gradient(1px 1px at 88% 12%, rgba(255,255,255,0.9) 0%, transparent 100%),
        radial-gradient(1px 1px at 20% 95%, rgba(255,255,255,0.5) 0%, transparent 100%),
        radial-gradient(1.5px 1.5px at 50% 80%, rgba(180,180,255,0.8) 0%, transparent 100%),
        radial-gradient(1px 1px at 65% 5%,  rgba(255,255,255,0.6) 0%, transparent 100%),
        radial-gradient(1px 1px at 95% 65%, rgba(255,255,255,0.4) 0%, transparent 100%),
        radial-gradient(1px 1px at 30% 20%, rgba(200,200,255,0.7) 0%, transparent 100%),
        radial-gradient(1px 1px at 85% 35%, rgba(255,255,255,0.5) 0%, transparent 100%);}
    .card{background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.15);border-radius:16px;
          padding:48px 40px;width:100%;max-width:540px;backdrop-filter:blur(12px);
          box-shadow:0 0 60px rgba(88,100,255,0.15);}
    h1{font-size:1.8rem;font-weight:800;color:#e6edf3;margin-bottom:6px;}
    h1 span{color:#58a6ff;}
    p{font-size:0.85rem;color:#8b949e;margin-bottom:32px;}
    label{font-size:0.75rem;text-transform:uppercase;letter-spacing:.1em;color:#8b949e;display:block;margin-bottom:6px;}
    input{width:100%;padding:12px 16px;background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.12);
          border-radius:8px;color:#e6edf3;font-size:0.95rem;outline:none;}
    input:focus{border-color:#58a6ff;}
    .row{display:flex;gap:10px;margin-top:10px;align-items:center;}
    .row label{margin:0;white-space:nowrap;}
    .row input[type=number]{width:90px;padding:8px 12px;}
    button{margin-top:24px;width:100%;padding:13px;background:#238636;border:none;border-radius:8px;
           color:#fff;font-size:1rem;font-weight:700;cursor:pointer;}
    button:hover{background:#2ea043;}
    {% if error %}.err{background:rgba(255,45,85,0.15);border:1px solid #ff2d55;border-radius:8px;
                       padding:12px 16px;margin-bottom:20px;color:#ff2d55;font-size:0.85rem;}{% endif %}
  </style>
</head>
<body>
<div class="card">
  <h1>&#x1F6E1; <span>WebSec</span> Scanner</h1>
  <p>Enter any URL to audit its security headers &amp; CORS configuration.</p>
  {% if error %}<div class="err">Warning: {{ error }}</div>{% endif %}
  <form method="POST" action="/scan">
    <label>Target URL</label>
    <input type="text" name="url" placeholder="https://example.com" required value="{{ last_url or '' }}"/>
    <div class="row">
      <label>Timeout (s)</label>
      <input type="number" name="timeout" value="10" min="3" max="60"/>
    </div>
    <button type="submit">&#x1F50D; Run Scan</button>
  </form>
</div>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(HOME_HTML, error=None, last_url="")


@app.route("/scan", methods=["POST"])
def run_scan():
    url     = request.form.get("url", "").strip()
    timeout = int(request.form.get("timeout", 10))
    if not url:
        return render_template_string(HOME_HTML, error="Please enter a URL.", last_url="")
    result = scan(url, timeout=timeout)
    if result.error:
        return render_template_string(HOME_HTML, error=f"Scan failed: {result.error}", last_url=url)
    header_findings = audit_headers(result.response_headers)
    cors_findings   = audit_cors(result.cors_probe_results)
    return build_report_html(result, header_findings, cors_findings, back_button=True)


if __name__ == "__main__":
    print("\n  WebSec Scanner running -> http://localhost:5000\n")
    app.run(debug=False, port=5000)
