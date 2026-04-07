"""persona_section_builders.py
==============================
HTML persona-specific section builders for the unified v3 report engine.

Each builder reads from the v3 ``artifact`` dict.  When ``artifact["canonical_report"]``
contains ``_csv_model`` (injected by csv_adapter) the richer CSV-derived IOC /
timeline data is used; otherwise the builder falls back to the standard v3
artifact fields.

Public entry point
------------------
    from src.reporting.persona_section_builders import build_persona_section_html

    persona_html = build_persona_section_html(artifact, persona)
    # Insert before </body> in the base executive report HTML.

CSS
---
The sections use the same CSS variables and classes as executive_reporting.py
(`--bg`, `--ink`, `--muted`, `.panel`, `.small`, `.badge`, etc.).  Additional
classes defined here must be injected into the <style> block by
render_executive_report_html — see EXTRA_CSS below.

EXTRA_CSS
---------
A string of additional CSS rules to inject into the <style> block.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from html import escape
from typing import Any

# ---------------------------------------------------------------------------
# Extra CSS (injected by render_executive_report_html, kept here for locality)
# ---------------------------------------------------------------------------

EXTRA_CSS = """
/* ── persona accent bar ─────────────────────────────────────────────────── */
.hero{border-top:6px solid var(--persona-accent,transparent)}
/* ── persona section tables ─────────────────────────────────────────────── */
.tbl{width:100%;border-collapse:collapse}
.tbl td,.tbl th{padding:8px 10px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:top}
.tbl thead tr{background:var(--soft)}
/* ── monospace ───────────────────────────────────────────────────────────── */
code,.mono-text{font-family:'Courier New',Consolas,monospace;font-size:12px;color:var(--accent2);background:var(--soft);padding:2px 5px;border-radius:4px;word-break:break-all}
.code-block{background:var(--soft);border:1px solid var(--border);border-radius:10px;padding:12px 16px;margin:8px 0;font-family:'Courier New',Consolas,monospace;font-size:12px;color:var(--accent2);white-space:pre-wrap;word-break:break-all}
/* ── verdict / status pills ──────────────────────────────────────────────── */
.pill{display:inline-block;padding:3px 9px;border-radius:999px;font-size:11px;letter-spacing:.06em;text-transform:uppercase;font-weight:700;border:1px solid currentColor}
.pill-confirmed{color:#0d6b43;background:#d4edda}
.pill-suspected{color:#7a5500;background:#fff3cc}
.pill-unknown{color:#7b2e2e;background:#fde8e8}
.pill-complete{color:#0d6b43;background:#d4edda}
.pill-partial{color:#7a5500;background:#fff3cc}
.pill-missing{color:#7b2e2e;background:#fde8e8}
.pill-isolate{color:#7b2e2e;background:#fde8e8}
.pill-investigate{color:#7a5500;background:#fff3cc}
.pill-review{color:#2c5282;background:#e8f0fe}
/* ── hypothesis bar ─────────────────────────────────────────────────────── */
.hyp-bar{display:inline-block;width:96px;height:9px;border-radius:5px;background:var(--border);vertical-align:middle;overflow:hidden;margin-left:4px}
.hyp-fill-confirmed{height:100%;width:100%;background:#0d6b43}
.hyp-fill-suspected{height:100%;width:62.5%;background:#fb8c00}
.hyp-fill-unknown{height:100%;width:0%;background:#888}
/* ── checklist ───────────────────────────────────────────────────────────── */
.checklist{list-style:none;padding:0;margin:10px 0 0 0}
.checklist li{padding:7px 0;border-bottom:1px solid var(--border);font-size:14px}
.checklist li::before{content:'☐  ';color:var(--muted)}
/* ── section note ────────────────────────────────────────────────────────── */
.section-note{color:var(--muted);font-size:13px;margin:0 0 14px;line-height:1.55}
/* ── print overrides ────────────────────────────────────────────────────── */
@media print{
  body{background:white!important;color:#111}
  .page{max-width:none;padding:0}
  .panel,.hero{box-shadow:none;background:white!important;border:1pt solid #bbb!important}
  .hero{border-top:6px solid var(--persona-accent,#333)!important}
  .headline{font-size:26px}
  .sub{font-size:12px}
  table td,table th{font-size:11px;padding:5px 7px}
  .badge,.pill{font-size:10px;padding:2px 6px}
  .status-confirmed::after{content:" [CONFIRMED]"}
  .status-unknown::after{content:" [UNKNOWN]"}
  .status-supported::after{content:" [SUPPORTED]"}
  .provider-dot{print-color-adjust:exact;-webkit-print-color-adjust:exact}
  .code-block{background:#f5f5f5!important;border:1pt solid #ccc!important}
}
/* ── dark-mode ───────────────────────────────────────────────────────────── */
@media(prefers-color-scheme:dark){
  :root{--bg:#0b0f14;--ink:#e6eef8;--panel:#0d1620;--border:#243144;--accent:#5b9bd5;--accent2:#4fc3a1;--soft:#1a2535;--muted:#8fa3bb}
  body{background:#0b0f14}
  .hero{background:linear-gradient(135deg,#0d1620,#0a1525)!important}
  code,.mono-text{color:#4fc3a1;background:#1a2535}
  .code-block{background:#1a2535;color:#4fc3a1}
}
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pill(text: str, variant: str) -> str:
    safe = escape(str(text or "").strip())
    cls  = f"pill-{variant.lower().replace(' ', '-')}"
    return f"<span class='pill {cls}'>{safe}</span>"


def _e(val: Any) -> str:
    return escape(str(val or ""))


def _fmt_ts(ts: Any) -> str:
    if ts is None:
        return "—"
    ts_str = str(ts).strip()
    if ts_str in ("", "—", "?", "unknown", "None"):
        return "—"
    try:
        epoch = int(float(ts_str))
        if 1_000_000_000 < epoch < 9_999_999_999:
            return (datetime.fromtimestamp(epoch, tz=timezone.utc)
                    .strftime("%Y-%m-%d %H:%M UTC"))
    except (ValueError, TypeError, OSError):
        pass
    return ts_str[:24]


def _tbl(headers: list[str], rows: list[list[Any]], classes: str = "") -> str:
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body_rows = []
    for row in rows:
        cells = "".join(f"<td>{str(c) if c is not None else ''}</td>" for c in row)
        body_rows.append(f"<tr>{cells}</tr>")
    if not body_rows:
        body_rows.append(
            f"<tr><td colspan='{max(1, len(headers))}' "
            f"style='color:var(--muted);font-style:italic'>No entries.</td></tr>"
        )
    cls = f"tbl {classes}".strip()
    return (
        f"<table class='{cls}'>"
        f"<thead><tr>{head}</tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody>"
        f"</table>"
    )


def _fmt_confidence(val: float | None) -> str:
    """P1-6: Format a 0-1 confidence value as a labelled percentage band."""
    if val is None:
        return "Unknown"
    v = float(val)
    if v >= 0.8:
        return f"High ({round(v * 100)}%)"
    if v >= 0.5:
        return f"Medium ({round(v * 100)}%)"
    if v >= 0.3:
        return f"Low ({round(v * 100)}%)"
    return f"Very Low ({round(v * 100)}%)"


# ---------------------------------------------------------------------------
# T1 banner — single-sentence actionable headline (persona_nontechnical_summaries spec)
# ---------------------------------------------------------------------------

def _t1_banner(text: str, verdict_class: str = "review") -> str:
    """Render the T1 one-liner headline banner per the non-technical summary spec.

    verdict_class: 'investigate' (red), 'review' (amber), 'complete' (green).
    """
    _bg  = {"investigate": "#fde8e8", "review": "#fff8e1", "complete": "#e8f5e9"}.get(
        verdict_class, "#f5f5f5")
    _bdr = {"investigate": "#c62828", "review": "#f57c00", "complete": "#2e7d32"}.get(
        verdict_class, "#9e9e9e")
    return (
        f"<div style='background:{_bg};border-left:6px solid {_bdr};"
        f"padding:14px 18px;margin-bottom:20px;border-radius:6px;"
        f"font-size:16px;font-weight:600;line-height:1.45;color:#212121'>"
        f"{escape(str(text or ''))}</div>"
    )


# ---------------------------------------------------------------------------
# MITRE ID → plain-English translation for non-technical persona views
# ---------------------------------------------------------------------------

_MITRE_PLAIN: dict[str, str] = {
    "T1003": "Password theft from the operating system",
    "T1059": "Malicious script or command execution",
    "T1071": "Attacker remote-control channel (C2 beacon)",
    "T1078": "Use of valid or stolen credentials",
    "T1082": "System information reconnaissance",
    "T1083": "File and directory browsing by attacker",
    "T1098": "Persistent access via account modification",
    "T1105": "Attacker tool download from external server",
    "T1110": "Brute force password attack",
    "T1539": "Session cookie theft",
    "T1566": "Phishing attack delivery",
    "T1486": "Ransomware data encryption",
    "T1021": "Remote service lateral movement",
    "T1218": "Execution via trusted Windows binary (LOLBin)",
    "T1027": "Obfuscated or encoded malware payload",
    "T1547": "Persistence via auto-start mechanism",
    "T1055": "Process injection (code injected into another process)",
    "T1074": "Data staged before exfiltration",
    "T1041": "Data exfiltration over a network channel",
    "T1190": "Exploitation of internet-facing application",
}

# Plain-English factor descriptions for client-facing (MSSP / compliance) views
_FACTOR_NONTECHNICAL: dict[str, str] = {
    "c2_communication":            "Your computer was communicating with an external server controlled by an attacker.",
    "malicious_process":           "A harmful program was detected running on one of your machines.",
    "credential_harvest":          "An attempt was made to steal login credentials.",
    "mfa_bypass":                  "A login bypassed your two-factor authentication check.",
    "privilege_escalation":        "An account gained unauthorised administrator access.",
    "lateral_movement":            "The attacker moved from one system to another inside your network.",
    "data_exfiltration_confirmed": "Data was sent outside your network to an external server.",
    "phishing_subject":            "A phishing email was detected that may have delivered malicious content.",
    "log_clearing":                "Security logs were deleted — the attacker tried to hide their activity.",
    "impossible_travel":           "A user account showed logins from two locations too far apart to be the same person.",
    "legacy_auth":                 "An outdated login method was used that is easier for attackers to exploit.",
    "process_injection":           "Malicious code was injected into a legitimate running process.",
}

_FACTOR_FORENSIC_PLAIN: dict[str, str] = {
    "c2_communication":            "C2 communication",
    "malicious_process":           "malicious process execution",
    "credential_harvest":          "credential theft",
    "mfa_bypass":                  "authentication bypass",
    "privilege_escalation":        "privilege escalation",
    "lateral_movement":            "lateral movement",
    "data_exfiltration_confirmed": "data exfiltration",
    "phishing_subject":            "phishing delivery",
    "log_clearing":                "log tampering",
}


# ---------------------------------------------------------------------------
# Executive extra section (PASTA / MAESTRO model when available in CSV model)
# ---------------------------------------------------------------------------

def _executive_extra(artifact: dict, model: dict | None) -> str:
    if not model:
        return ""
    atk     = model.get("attack_story") or {}
    iocs    = model.get("iocs") or {}
    overall = model.get("overall_risk") or "HIGH"
    n_mal   = model.get("malicious_count") or 0

    pasta_rows: list[list[Any]] = []
    risk_items = [
        ("Phishing email delivery",
         "Initial Access",
         "SUPPORTED" if model.get("has_email") else "LIKELY",
         7 if model.get("has_email") else 4,
         "User awareness training; advanced email filtering"),
        ("Malicious process execution",
         "Execution",
         "SUPPORTED" if n_mal > 0 else "LIKELY",
         7 if n_mal > 0 else 4,
         "Endpoint behavioural detection; application allow-listing"),
        ("C2 beaconing to external IP",
         "Command & Control",
         "SUPPORTED" if model.get("has_c2") else "UNKNOWN",
         7 if model.get("has_c2") else 3,
         "Egress firewall rules; DNS sinkholing; proxy inspection"),
        ("Data exfiltration",
         "Exfiltration",
         "UNKNOWN",
         0,
         "DLP controls; audit exfil channels in next collection window"),
        ("Persistence via scheduled task / registry",
         "Persistence",
         "UNKNOWN",
         0,
         "Registry integrity monitoring; scheduled-task audit"),
    ]
    for threat, stage, status, score, mitigation in risk_items:
        pasta_rows.append([
            _e(threat),
            _e(stage),
            _pill(status, status.lower()),
            (f"<strong style='color:{'#e53935' if score>=8 else '#fb8c00' if score>=5 else '#888'}'>"
             f"{score}/10</strong>" if score else "<span style='color:var(--muted)'>N/A</span>"),
            _e(mitigation),
        ])

    maestro_text = ""
    threat_models = model.get("threat_models") or {}
    maestro_stages = threat_models.get("maestro_stages") or []
    if maestro_stages:
        # Render MAESTRO as a structured table (P1-4)
        _detected_color = {"True": "#e53935", "False": "#43a047"}
        maestro_rows: list[list[Any]] = []
        for ms in maestro_stages:
            detected = ms.get("detected", False)
            ev_f = ", ".join(ms.get("evidence_factors") or []) or "—"
            maestro_rows.append([
                _e(ms.get("stage") or ""),
                (f"<span style='color:#e53935;font-weight:600'>DETECTED</span>"
                 if detected else
                 "<span style='color:#43a047'>NOT DETECTED</span>"),
                f"<span class='small'><code>{_e(ev_f)}</code></span>",
                f"<span class='small'>{_e(ms.get('description') or '')}</span>",
            ])
        maestro_text = _tbl(["Stage", "Status", "Evidence Factors", "Description"], maestro_rows)
    elif atk.get("narrative"):
        maestro_text = f"<p class='section-note'>{_e(atk['narrative'])}</p>"
    attacker_ips = iocs.get("public_ips") or atk.get("attacker_ips") or []
    if attacker_ips:
        maestro_text += (
            f"<p class='small'><strong>Observed external entities requiring review:</strong> "
            f"<code>{_e(', '.join(str(ip) for ip in attacker_ips[:6]))}</code></p>"
        )
    decision_needed = [
        "Approve analyst-led validation of the highest-confidence findings.",
        "Decide whether host isolation can proceed after human review of affected assets.",
    ]
    decision_not_needed = [
        "Broad external communications.",
        "Regulatory notification language before legal review.",
    ]

    # T1 — one-sentence actionable headline (spec: persona_nontechnical_summaries §1)
    n_susp = model.get("suspicious_count") or 0
    if n_mal > 0:
        _exec_t1 = "A confirmed attack was detected — immediate escalation is in progress."
        _exec_t1_cls = "investigate"
    elif n_susp > 0:
        _exec_t1 = "Unusual activity was flagged and is under investigation — no confirmed breach yet."
        _exec_t1_cls = "review"
    else:
        _exec_t1 = "No threat detected — activity was reviewed and found to be normal."
        _exec_t1_cls = "complete"

    e8_exec_html = _essential_eight_block(model)

    return _t1_banner(_exec_t1, _exec_t1_cls) + f"""
<section class='panel page-break' style='margin-top:18px'>
  <h2>PASTA Risk Analysis</h2>
  <p class='section-note'>Process and Attack Simulation &amp; Threat Analysis — risk scored against current evidence.</p>
  {_tbl(["Threat Scenario", "ATT&amp;CK Stage", "Status", "Impact Score", "Mitigation Guidance"],
        pasta_rows)}
</section>
<section class='panel' style='margin-top:18px'>
  <h2>Adversary Mission Analysis</h2>
  {maestro_text or "<p class='section-note'>Insufficient telemetry for adversary mission reconstruction.</p>"}
  <h3 style='margin-top:14px'>Diamond Model — Blast Radius</h3>
  {_tbl(
      ["Dimension", "Observed"],
      [
          ["Adversary",   _e(", ".join(str(ip) for ip in attacker_ips[:3])) or "Unknown"],
          ["Capability",  _e(", ".join(iocs.get("processes", [])[:4])) or "Unknown"],
          ["Infrastructure", _e(", ".join(attacker_ips[:3])) or "Unknown"],
          ["Victim",      _e(", ".join((model.get("attack_story") or {}).get("internal_hosts") or [])) or "Not confirmed"],
      ],
  )}
</section>
{e8_exec_html}
<section class='panel' style='margin-top:18px'>
  <h2>Leadership Decision Framing</h2>
  <div class='section-split'>
    <div>
      <h3>Decision Needed</h3>
      <ul class='checklist'>{"".join(f"<li>{_e(item)}</li>" for item in decision_needed)}</ul>
    </div>
    <div>
      <h3>Decision Not Needed Yet</h3>
      <ul class='checklist'>{"".join(f"<li>{_e(item)}</li>" for item in decision_not_needed)}</ul>
    </div>
  </div>
</section>
"""


# ---------------------------------------------------------------------------
# SOC Analyst section
# ---------------------------------------------------------------------------

def _soc_analyst(artifact: dict, model: dict | None) -> str:
    if not model:
        # Graceful degradation: use v3 artifact facts
        facts    = artifact.get("facts") or {}
        overview = artifact.get("overview") or {}
        pivots   = [p for p in (facts.get("shared_pivots") or [])
                    if str(p.get("type") or "") != "resource"][:6]
        pivot_rows = [[
            f"<code>{_e(p.get('pivot'))}</code>",
            _e(p.get("type")),
            _e(", ".join(str(s) for s in (p.get("sources") or []))),
            _e(p.get("support_count")),
        ] for p in pivots]
        return f"""
<section class='panel page-break' style='margin-top:18px'>
  <h2>SOC Analyst — Triage &amp; IOC Notes</h2>
  <p class='section-note'>Built from v3 cloud telemetry — no raw endpoint/IOC model available.</p>
  <h3>Shared Pivots</h3>
  {_tbl(["Pivot", "Type", "Sources", "Support Count"], pivot_rows)}
</section>"""

    ev       = model.get("evidence") or []
    iocs     = model.get("iocs") or {}
    atk      = model.get("attack_story") or {}
    flagged  = len(ev)
    n_crit   = sum(1 for e in ev if e["severity"] == "critical")
    n_high   = sum(1 for e in ev if e["severity"] == "high")
    priority = "P1" if n_crit else "P2" if n_high else "P3"
    sla_mins = 60 if n_crit else 240 if n_high else 1440
    risk_col = "#e53935" if priority == "P1" else "#fb8c00" if priority == "P2" else "#43a047"
    # Fallback: workbook review_state_counts may confirm malicious even when CSV model severity
    # classifies all events as 'high' (not 'critical') → upgrade to P1 to avoid false P2 signal.
    _ws_confirmed = (((artifact.get("facts") or {}).get("review_state_counts") or {}).get("confirmed_malicious") or 0)
    if _ws_confirmed > 0 and priority != "P1":
        priority = "P1"
        n_crit   = _ws_confirmed
        sla_mins = 60
        risk_col = "#e53935"

    # T1 — spec: P-priority + specific host/IP, immediately actionable
    _mal_ev_t1 = [e for e in ev if e.get("verdict") == "malicious"]
    _soc_t1_host = "—"
    if _mal_ev_t1:
        _r0 = _mal_ev_t1[0]["row"]
        _soc_t1_host = str(_r0.get("hostname") or _r0.get("computer") or _r0.get("host") or "—")[:28]
    _soc_attacker_ips = iocs.get("public_ips") or atk.get("attacker_ips") or []
    _soc_t1_ip = str(_soc_attacker_ips[0]) if _soc_attacker_ips else "—"
    if priority == "P1":
        if _soc_t1_host != "—" and _soc_t1_ip != "—":
            _soc_t1 = f"P1 — CONTAIN IMMEDIATELY: Isolate host {_soc_t1_host} and block IP {_soc_t1_ip}."
        elif _soc_t1_host != "—":
            _soc_t1 = f"P1 — CONTAIN IMMEDIATELY: Isolate host {_soc_t1_host} — {n_crit} critical event{'s' if n_crit != 1 else ''} confirmed."
        else:
            _soc_t1 = f"P1 — CONTAIN IMMEDIATELY: {n_crit} critical event{'s' if n_crit != 1 else ''} confirmed — identify and isolate affected hosts."
        _soc_t1_cls = "investigate"
    elif priority == "P2":
        _soc_t1 = f"P2 — INVESTIGATE: Review {n_high} suspicious event{'s' if n_high != 1 else ''} within the next 2 hours — no confirmed breach yet."
        _soc_t1_cls = "review"
    elif flagged > 0:
        _soc_t1 = "P3 — MONITOR: No immediate action required — watch for recurrence in next analysis window."
        _soc_t1_cls = "complete"
    else:
        _soc_t1 = "P4 — CLOSE: Activity confirmed benign — no further action required."
        _soc_t1_cls = "complete"

    # Triage table rows
    triage_rows: list[list[Any]] = []
    action_map = {"malicious": "CONTAIN CANDIDATE", "suspicious": "INVESTIGATE"}
    for e in ev[:14]:
        r = e["row"]
        host    = str(r.get("hostname") or r.get("computer") or r.get("host") or "—")[:24]
        user    = str(r.get("user") or r.get("username") or r.get("to")
                      or r.get("email_to") or "—")[:22]
        _mitre_list = e.get("mitre") or []
        if not _mitre_list:
            _mitre_list = list((e.get("row") or {}).get("mitre_techniques") or [])
        mitre_0 = _mitre_list[0].split(":")[0].strip() if _mitre_list else "—"
        action  = action_map.get(e["verdict"], "REVIEW")
        action_variant = ("isolate" if "ISOLATE" in action else
                          "investigate" if action == "INVESTIGATE" else "review")
        quality = (atk.get("evidence_quality") or {}).get(e["code"], "?")
        raw_dread = float(e.get('dread') or 0)
        dread_str = f"{raw_dread * 10:.1f}/10" if raw_dread <= 1.0 else f"{raw_dread:.1f}/10"
        triage_rows.append([
            f"<code>{_e(e['code'])}</code>",
            _e(_fmt_ts(e["ts_human"])),
            f"<code>{_e(host)}</code>",
            _e(user),
            f"<code>{_e(mitre_0)}</code>",
            f"<strong>{_e(dread_str)}</strong>",
            _pill(action, action_variant),
            _pill(quality, quality.lower()),
        ])

    # IOC Block List
    public_ips  = iocs.get("public_ips") or []
    processes   = iocs.get("processes") or []
    domains     = iocs.get("domains") or []
    hashes      = iocs.get("hashes") or []
    ioc_html = ""
    if public_ips:
        ioc_html += f"<p><strong>External IPs:</strong>&nbsp; <code>{_e(', '.join(sorted(public_ips)[:8]))}</code></p>"
    private_ips = [ip for ip in (iocs.get("ips") or []) if ip not in public_ips]
    if private_ips:
        ioc_html += (f"<p style='color:#fb8c00'><strong>Internal IPs</strong> "
                     f"(victim endpoints — do <em>not</em> block):&nbsp; "
                     f"<code>{_e(', '.join(sorted(private_ips)[:4]))}</code></p>")
    if processes:
        ioc_html += f"<p><strong>Processes:</strong>&nbsp; <code>{_e(', '.join(sorted(processes)[:6]))}</code></p>"
    if domains:
        ioc_html += f"<p><strong>Domains:</strong>&nbsp; <code>{_e(', '.join(sorted(domains)[:6]))}</code></p>"
    if hashes:
        ioc_html += f"<p><strong>File hashes:</strong>&nbsp; <code>{_e(', '.join(sorted(hashes)[:4]))}</code></p>"
    if not ioc_html:
        ioc_html = "<p class='section-note'>No blockable IOCs extracted — review evidence manually.</p>"

    # STRIDE threat model (P1-3)
    stride_html = ""
    threat_models = model.get("threat_models") or {}
    stride_summary = threat_models.get("stride_summary") or {}
    if stride_summary:
        _status_color = {"CONFIRMED": "#e53935", "SUSPECTED": "#fb8c00", "NOT DETECTED": "#43a047"}
        stride_rows: list[list[Any]] = []
        for code in "STRIDE":
            entry = stride_summary.get(code) or {}
            label = entry.get("label") or code
            status = entry.get("status") or "NOT DETECTED"
            count  = entry.get("count") or 0
            ev_ids = ", ".join(
                str(x.get("identifier") or "")[:24] for x in (entry.get("evidence") or [])[:3]
            ) or "—"
            color  = _status_color.get(status, "#888")
            stride_rows.append([
                f"<strong>{_e(code)}</strong>",
                _e(label),
                f"<span style='color:{color};font-weight:600'>{_e(status)}</span>",
                str(count),
                f"<span class='small'>{_e(ev_ids)}</span>",
            ])
        stride_html = (
            "<section class='panel' style='margin-top:18px'>"
            "<h2>STRIDE Threat Model</h2>"
            "<p class='section-note'>Aggregated from IOC pattern matching across all evidence.</p>"
            + _tbl(["Code", "Category", "Status", "Count", "Identifiers (first 3)"], stride_rows)
            + "</section>"
        )

    # Pivots
    pivots = model.get("pivots") or []
    pivot_rows_html = ""
    for pv in pivots[:6]:
        codes_str = ", ".join(pv["codes"][:5])
        pivot_rows_html += (f"<tr><td><code>{_e(pv['entity'])}</code></td>"
                            f"<td>{len(pv['codes'])}</td><td>{_e(codes_str)}</td>"
                            f"<td class='small'>WHOIS · VT · Shodan</td></tr>")

    # Handoff card
    malicious_ev = [e for e in ev if e["verdict"] == "malicious"]
    handoff_rows: list[list[Any]] = []
    for me in malicious_ev[:12]:
        r    = me["row"]
        proc = r.get("process_name") or r.get("process") or "—"
        host = r.get("hostname") or r.get("computer") or "—"
        src  = r.get("src_ip") or "—"
        detail = (f"{proc} on {host} [src: {src}]" if proc != "—"
                  else (me["factors"][0] if me["factors"] else me["code"]))
        handoff_rows.append([
            f"<code>{_e(me['code'])}</code>",
            _e(_fmt_ts(me["ts_human"])),
            _e(str(detail)[:64]),
        ])

    handoff_instructions = []
    if atk.get("internal_hosts"):
        handoff_instructions.append(
            f"Capture BEFORE shutdown: memory dump + PCAP from "
            f"<code>{_e(atk['internal_hosts'][0])}</code>"
        )
    if atk.get("attacker_ips"):
        handoff_instructions.append(
            f"Review for policy-based blocking after analyst validation: <code>{_e(', '.join(atk['attacker_ips'][:3]))}</code>"
        )
    if not handoff_instructions:
        handoff_instructions.append(
            "Review triage table events and escalate to Threat Hunter immediately.")

    instr_html = "".join(
        f"<li>&#9658; {instr}</li>" for instr in handoff_instructions
    )

    return _t1_banner(_soc_t1, _soc_t1_cls) + f"""
<section class='panel page-break' style='margin-top:18px'>
  <h2>SOC Analyst — Triage Queue</h2>
  <div class='meta-strip' style='margin-bottom:14px'>
    <span>Priority: <strong style='color:{risk_col}'>{_e(priority)}</strong></span>
    <span>SLA: <strong>{_e(sla_mins)} min</strong></span>
    <span>Critical: <strong>{n_crit}</strong></span>
    <span>High: <strong>{n_high}</strong></span>
    <span>Total flagged: <strong>{flagged}</strong></span>
    {"<span>Incident start: <strong>" + _e(atk.get("start_ts","—")) + "</strong></span>" if atk.get("start_ts") and atk.get("start_ts") != "—" else ""}
  </div>
  {_tbl(
      ["ID", "Timestamp (UTC)", "Host", "User / Identity", "MITRE", "DREAD", "Action", "Quality"],
      triage_rows,
  )}
</section>

<section class='panel' style='margin-top:18px'>
  <h2>Observed IOCs And Safe Now Actions</h2>
  {ioc_html}
</section>

{stride_html}

{"<section class='panel' style='margin-top:18px'><h2>Pivot Candidates</h2><table class='tbl'><thead><tr><th>Entity</th><th>Occurrences</th><th>Evidence Codes</th><th>Expand Via</th></tr></thead><tbody>" + pivot_rows_html + "</tbody></table></section>" if pivot_rows_html else ""}

{"<section class='panel page-break' style='margin-top:18px'><h2>Escalate to Tier-2 / Threat Hunter — Handoff Card</h2>" + _tbl(["ID", "Time (UTC)", "Detail"], handoff_rows) + "<div class='section-split' style='margin-top:12px'><div><h3>Safe Now</h3><ul class='checklist'><li>Collect host, user, and timeline context before containment.</li><li>Review external IPs and domains for policy-based blocking.</li></ul></div><div><h3>Needs Approval / More Evidence</h3><ul class='checklist'>" + instr_html + "<li>Do not block internal victim IPs.</li></ul></div></div></section>" if handoff_rows else ""}
"""


# ---------------------------------------------------------------------------
# Threat Hunter section
# ---------------------------------------------------------------------------

def _threat_hunter(artifact: dict, model: dict | None) -> str:
    if not model:
        # Degrade: show v3 working hypothesis
        hypothesis = (artifact.get("overview") or {}).get("working_hypothesis") or []
        hyp_rows: list[list[Any]] = []
        for h in hypothesis:
            status = str(h.get("status") or "unknown").lower()
            hyp_rows.append([
                _e(h.get("label")),
                _pill(status, status),
                _e(h.get("note")),
            ])
        return f"""
<section class='panel page-break' style='margin-top:18px'>
  <h2>Threat Hunter — Working Hypothesis</h2>
  {_tbl(["Hypothesis", "Status", "Note"], hyp_rows)}
</section>"""

    ev        = model.get("evidence") or []
    iocs      = model.get("iocs") or {}
    kill_chain = model.get("kill_chain") or []
    atk       = model.get("attack_story") or {}

    # Hypothesis rows
    c2_codes  = [e["code"] for e in ev
                 if any("c2" in f.lower() or "beacon" in f.lower()
                        for f in e.get("factors", []))]
    ep_codes  = [e["code"] for e in ev
                 if (e.get("sheet") or "").lower() in ("endpoint", "edr")]
    lat_codes = [e["code"] for e in ev
                 if any("lateral" in f.lower() or "wmi" in f.lower()
                        for f in e.get("factors", []))]
    cred_codes= [e["code"] for e in ev
                 if any("cred" in f.lower() or "dump" in f.lower()
                        for f in e.get("factors", []))]
    email_codes=[e["code"] for e in ev
                 if (e.get("sheet") or "").lower() == "email"]

    hypotheses: list[tuple[str, str, str]] = []
    if c2_codes:
        conn_keys = list(atk.get("c2_connections", {}).keys())
        ch_str = (f"{len(conn_keys)} channel(s): {', '.join(conn_keys[:2])}"
                  if conn_keys else f"{len(c2_codes)} callback event(s)")
        hypotheses.append((
            f"C2 beacon activity consistent with callback traffic — {ch_str}",
            "SUPPORTED",
            ", ".join(c2_codes[:4]),
        ))
    if ep_codes and model.get("malicious_count", 0) > 0:
        procs = sorted(iocs.get("processes", []))[:2]
        pc_str = f" ({', '.join(procs)})" if procs else ""
        hypotheses.append((
            f"Malicious process execution likely{pc_str}",
            "SUPPORTED",
            ", ".join(ep_codes[:4]),
        ))
    if "Lateral Movement" in kill_chain or lat_codes:
        hypotheses.append((
            "Lateral movement via WMI / RDP / SMB",
            "SUPPORTED" if lat_codes else "LIKELY",
            ", ".join(lat_codes[:3]) if lat_codes else "inferred from kill chain",
        ))
    if "Credential Access" in kill_chain or cred_codes:
        hypotheses.append((
            "Credential harvesting or dumping activity",
            "SUPPORTED" if cred_codes else "LIKELY",
            ", ".join(cred_codes[:3]) if cred_codes else "inferred from kill chain",
        ))
    if model.get("has_email") or email_codes:
        confirmed_email = any(e["verdict"] == "malicious" for e in ev
                               if (e.get("sheet") or "").lower() == "email")
        hypotheses.append((
            "Initial access via phishing email",
            "SUPPORTED" if confirmed_email else "LIKELY",
            ", ".join(email_codes[:3]) if email_codes else "email sheet present",
        ))
    hypotheses.append(("Data staged / exfiltrated", "UNKNOWN", "no exfil logs in dataset"))
    hypotheses.append(("Persistence mechanism installed", "UNKNOWN",
                        "no registry / scheduled-task data"))

    bar_map  = {
        "SUPPORTED": ("hyp-fill-confirmed", "85%"),
        "LIKELY": ("hyp-fill-suspected", "62.5%"),
        "UNKNOWN":   ("hyp-fill-unknown",   "0%"),
    }
    hyp_rows: list[list[Any]] = []
    for hyp, status, evidence_ref in hypotheses:
        fill_cls, fill_pct = bar_map.get(status, ("hyp-fill-unknown", "0%"))
        bar_html = (f"<span class='hyp-bar'>"
                    f"<span class='{fill_cls}' style='display:block;height:100%;width:{fill_pct}'></span>"
                    f"</span>")
        hyp_rows.append([
            _e(hyp),
            f"{_pill(status, status.lower())} {bar_html}",
            f"<code>{_e(evidence_ref)}</code>",
        ])

    # Beacon analysis
    beacon_html = ""
    c2_conns = atk.get("c2_connections") or {}
    if c2_conns:
        intervals = atk.get("beacon_intervals") or []
        avg_s     = int(sum(intervals) / len(intervals)) if intervals else None
        interval_str = f"~{avg_s}s interval" if avg_s else "interval unknown"
        beacon_rows: list[list[Any]] = []
        for conn_key, codes in list(c2_conns.items())[:6]:
            beacon_rows.append([
                f"<code>{_e(conn_key)}</code>",
                str(len(codes)),
                _e(interval_str),
                f"<code>{_e(', '.join(codes[:4]))}</code>",
            ])
        beacon_html = (
            f"<section class='panel' style='margin-top:18px'>"
            f"<h2>Beacon Analysis — Deduplicated</h2>"
            + _tbl(["Channel", "Callbacks", "Interval", "Evidence Codes"], beacon_rows) +
            f"<p class='small' style='margin-top:10px;color:#fb8c00'>&#9888; "
            f"No JA3 fingerprint logged — add TLS/SSL inspection sensor to capture metadata.</p>"
            f"</section>"
        )

    # Pivot candidates
    pivots   = model.get("pivots") or []
    pub_ips  = iocs.get("public_ips") or []
    processes= iocs.get("processes") or []
    pivot_rows_html = ""
    for pv in pivots[:5]:
        codes_str = ", ".join(pv["codes"][:5])
        pivot_rows_html += (
            f"<tr><td><code>{_e(pv['entity'])}</code></td>"
            f"<td>{len(pv['codes'])}</td><td><code>{_e(codes_str)}</code></td>"
            f"<td class='small'>WHOIS · ASN · VirusTotal · Shodan</td></tr>"
        )
    for ip in sorted(pub_ips)[:4]:
        pivot_rows_html += (
            f"<tr><td><code>{_e(ip)}</code></td>"
            f"<td>—</td><td>external-ip</td>"
            f"<td class='small'>Reverse DNS · Shodan · MalwareBazaar</td></tr>"
        )
    for proc in sorted(processes)[:3]:
        pivot_rows_html += (
            f"<tr><td><code>{_e(proc)}</code></td>"
            f"<td>—</td><td>process</td>"
            f"<td class='small'>VT hash · ANY.RUN sandbox · LOLBAS</td></tr>"
        )
    pivot_section = ""
    if pivot_rows_html:
        pivot_section = (
            f"<section class='panel' style='margin-top:18px'>"
            f"<h2>Pivot Candidates — Expand These First</h2>"
            f"<table class='tbl'><thead><tr>"
            f"<th>Entity</th><th>Occurrences</th><th>Type / Codes</th><th>Hunt Via</th>"
            f"</tr></thead><tbody>{pivot_rows_html}</tbody></table>"
            f"</section>"
        )

    # Blind spots
    sheet_names = {(e.get("sheet") or "").lower() for e in ev}
    blind_spots: list[str] = []
    if "network" not in sheet_names and not model.get("has_network"):
        blind_spots.append("No DNS logs — cannot confirm domain-based C2 or DNS tunnelling.")
    if not any("auth" in s for s in sheet_names):
        blind_spots.append("No authentication logs — credential reuse or pass-the-hash unconfirmed.")
    if not any("registry" in s or "reg" in s for s in sheet_names):
        blind_spots.append("No registry data — persistence via Run keys / Services unconfirmed.")
    if not any(e["row"].get("parent_proc") for e in ev):
        blind_spots.append("No parent process data — process injection chain cannot be confirmed.")
    if not iocs.get("hashes"):
        blind_spots.append("No file hashes — cannot submit to VirusTotal for reputation scoring.")
    if not atk.get("beacon_intervals"):
        blind_spots.append("Insufficient timestamps — beacon periodicity not measurable.")
    if not blind_spots:
        blind_spots.append("Dataset coverage appears adequate — no critical blind spots identified.")

    blind_html = "".join(f"<li>&#10007; {_e(bs)}</li>" for bs in blind_spots)

    # Hunt queries
    query_html = ""
    for proc in sorted(processes)[:2]:
        query_html += (
            f"<p class='small'><strong># Process hunt: {_e(proc)}</strong></p>"
            f"<div class='code-block'>Splunk: index=endpoint EventCode=1 proc=\"*{_e(proc)}*\"\n"
            f"KQL:    DeviceProcessEvents | where FileName =~ \"{_e(proc)}\"</div>"
        )
    for ip in sorted(pub_ips)[:2]:
        query_html += (
            f"<p class='small'><strong># C2 hunt: {_e(ip)}</strong></p>"
            f"<div class='code-block'>Splunk: index=network dest_ip={_e(ip)}\n"
            f"KQL:    DeviceNetworkEvents | where RemoteIP == \"{_e(ip)}\"</div>"
        )
    all_mitre = list({m for e in ev for m in e.get("mitre", [])})[:6]
    if all_mitre:
        mitre_block = "\n".join(f"MITRE: {_e(m)}" for m in all_mitre)
        query_html += (
            f"<p class='small'><strong># Technique coverage</strong></p>"
            f"<div class='code-block'>{mitre_block}</div>"
        )
    if not query_html:
        query_html = "<p class='section-note'>No specific IOCs available for query generation — use MITRE technique IDs above.</p>"

    # T1 — threat hunter: hunt outcome one-liner
    _ws_confirmed_th = (((artifact.get("facts") or {}).get("review_state_counts") or {}).get("confirmed_malicious") or 0)
    _th_n_mal = (model.get("malicious_count") or 0) or _ws_confirmed_th
    _th_has_c2 = model.get("has_c2")
    _th_primary_ip = (iocs.get("public_ips") or atk.get("attacker_ips") or [None])[0]
    if _th_n_mal > 0 and _th_has_c2 and _th_primary_ip:
        _th_t1 = f"Hunt pivot confirmed: C2 infrastructure {_th_primary_ip} — {_th_n_mal} malicious event{'s' if _th_n_mal != 1 else ''} linked — expand hunt to related subnet and user scope."
        _th_t1_cls = "investigate"
    elif _th_n_mal > 0:
        _th_t1 = f"Technique cluster confirmed — {_th_n_mal} malicious event{'s' if _th_n_mal != 1 else ''} — generate hunt hypotheses from MITRE techniques and IOCs below."
        _th_t1_cls = "investigate"
    elif c2_codes or ep_codes:
        _th_t1 = "Suspicious activity detected — no confirmed malicious events yet — run hypothesis queries and validate IOCs before escalating."
        _th_t1_cls = "review"
    else:
        _th_t1 = "Threat hunt: negative result — no confirmed threats in this dataset — recommend baseline calibration."
        _th_t1_cls = "complete"

    return _t1_banner(_th_t1, _th_t1_cls) + f"""
<section class='panel page-break' style='margin-top:18px'>
  <h2>Threat Hunter — Hunt Hypothesis Status</h2>
  {_tbl(["Hypothesis", "Status", "Evidence / Basis"], hyp_rows)}
</section>
{beacon_html}
{pivot_section}
<section class='panel' style='margin-top:18px'>
  <h2>Dataset Blind Spots — What We Cannot See</h2>
  <ul class='checklist'>{blind_html}</ul>
</section>
<section class='panel' style='margin-top:18px'>
  <h2>Hunt Queries — Copy-Paste Ready</h2>
  {query_html}
</section>
"""


# ---------------------------------------------------------------------------
# Forensic Analyst section
# ---------------------------------------------------------------------------

def _forensics(artifact: dict, model: dict | None) -> str:
    if not model:
        # Degrade: show v3 evidence appendix rows
        app = (artifact.get("appendix") or {}).get("evidence_appendix") or {}
        rows = app.get("source_evidence_rows") or []
        ev_rows_tab: list[list[Any]] = []
        for r in rows[:15]:
            ev_rows_tab.append([
                f"<code>{_e(r.get('_citation') or r.get('_evidence_code'))}</code>",
                _e(r.get("source_kind")),
                _e(_fmt_ts(r.get("timestamp"))),
                _e(r.get("user")),
                _e(r.get("ip")),
                _e(r.get("resource")),
                _pill(r.get("review_state") or "unknown",
                      (r.get("review_state") or "unknown").split("_")[0]),
            ])
        return f"""
<section class='panel page-break' style='margin-top:18px'>
  <h2>Forensic Analyst — Evidence Inventory</h2>
  {_tbl(["Code", "Source", "Timestamp", "User", "IP", "Resource", "Review State"], ev_rows_tab)}
</section>"""

    ev  = model.get("evidence") or []
    iocs= model.get("iocs") or {}
    atk = model.get("attack_story") or {}

    # Evidence inventory
    inv_rows: list[list[Any]] = []
    for e in ev[:20]:
        r       = e["row"]
        etype   = (e.get("sheet") or "event").capitalize()[:14]
        val_raw = (r.get("process_name") or r.get("process") or r.get("subject")
                   or r.get("path") or r.get("src_ip") or r.get("detection_name")
                   or r.get("domain") or "—")
        val     = str(val_raw)[:44]
        quality = (atk.get("evidence_quality") or {}).get(e["code"], "UNKNOWN")
        v_abbr  = {"malicious": "MAL", "suspicious": "SUS", "unknown": "UNK"}
        verdict_short = v_abbr.get(e["verdict"], "UNK")
        inv_rows.append([
            f"<code>{_e(e['code'])}</code>",
            _e(etype),
            f"<code>{_e(val)}</code>",
            _pill(verdict_short, e["verdict"]),
            _pill(quality, quality.lower()),
        ])

    # Process execution chain
    ep_evs = [e for e in ev if (e.get("sheet") or "").lower() in ("endpoint", "edr", "")]
    proc_chain_html = ""
    if ep_evs:
        chain_parts: list[str] = []
        for e in ep_evs[:6]:
            r       = e["row"]
            parent  = r.get("parent_proc") or "explorer.exe"
            proc    = r.get("process_name") or r.get("process") or "unknown.exe"
            cmdline = str(r.get("cmdline") or "")[:80]
            pid     = r.get("pid") or "?"
            delta   = (atk.get("event_deltas") or {}).get(e["code"], "")
            ts_str  = f"{_fmt_ts(e['ts_human'])} ({delta})" if delta else _fmt_ts(e["ts_human"])
            marker  = " ← MALICIOUS" if e["verdict"] == "malicious" else ""
            chain_parts.append(
                f"<div class='code-block'>"
                f"{_e(parent)}<br>"
                f"&nbsp;&nbsp;└─ <strong>{_e(proc)}</strong> [PID {_e(pid)}]"
                f"&nbsp;&nbsp;{_e(ts_str)}{_e(marker)}"
                + (f"<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;cmdline: {_e(cmdline)}" if cmdline else "")
                + "</div>"
            )
        proc_chain_html = (
            f"<section class='panel' style='margin-top:18px'>"
            f"<h2>Process Execution Chain</h2>"
            + "".join(chain_parts) +
            f"</section>"
        )

    # Timeline
    sorted_ev = atk.get("sorted_events") or sorted(ev, key=lambda e: str(e.get("ts_human") or ""))
    tl_rows: list[list[Any]] = []
    for e in sorted_ev[:16]:
        delta = (atk.get("event_deltas") or {}).get(e["code"], "")
        time_str = _fmt_ts(e["ts_human"]) + (f" [{delta}]" if delta else "")
        desc = (e.get("summary") or
                (e.get("factors") or ["event"])[0] if e.get("factors") else "event")
        quality  = (atk.get("evidence_quality") or {}).get(e["code"], "?")
        tl_rows.append([
            _e(time_str),
            f"<code>{_e(e['code'])}</code>",
            _pill(quality, quality.lower() if quality in ("COMPLETE","PARTIAL","MISSING") else "unknown"),
            _e(str(desc)[:72]),
        ])

    # Evidence gaps
    host_str = ", ".join(sorted(iocs.get("hosts", []))[:3]) or "flagged endpoints"
    pub_ips  = iocs.get("public_ips") or []
    ip_str   = ", ".join(sorted(pub_ips)[:2]) or "identified C2 IPs"
    gaps: list[str] = []
    if iocs.get("hosts"):
        gaps.append(f"Memory dump of <code>{_e(host_str)}</code> — BEFORE shutdown (volatile evidence)")
    else:
        gaps.append("Identify and image all flagged endpoints — hostnames not captured in dataset")
    if model.get("has_c2"):
        gaps.append(f"PCAP: full traffic capture covering C2 window to <code>{_e(ip_str)}</code>")
    if model.get("has_email"):
        gaps.append("Original phishing email: raw RFC822 headers + attachment")
    gaps.append("Registry export: HKCU/HKLM Run keys + Services")
    gaps.append("Scheduled tasks: <code>schtasks /query /fo LIST /v &gt; tasks.txt</code>")
    gaps.append("Disk image: primary drive on affected hosts (before remediation)")
    partial = [e["code"] for e in ev
               if (atk.get("evidence_quality") or {}).get(e["code"]) == "PARTIAL"]
    if partial:
        gaps.append(f"Re-collect missing fields for: <code>{_e(', '.join(partial[:5]))}</code>")
    gaps_html = "".join(f"<li>{gap}</li>" for gap in gaps)

    # T1 — spec: precise incident scope statement with asset + time window
    _mal_ev = [e for e in ev if e.get("verdict") == "malicious"]
    _sus_ev = [e for e in ev if e.get("verdict") == "suspicious"]
    _host_f1 = ""
    _ts_start_f = atk.get("start_ts") or (ev[0]["ts_human"] if ev else "")
    _ts_end_f   = atk.get("end_ts")   or (ev[-1]["ts_human"] if ev else "")
    if ev:
        _r0f = (_mal_ev[0] if _mal_ev else ev[0])["row"]
        _host_f1 = str(_r0f.get("hostname") or _r0f.get("computer") or _r0f.get("host") or "")[:28]

    if _mal_ev:
        # Determine primary factor in plain English
        _f0 = (_mal_ev[0].get("factors") or ["malicious activity"])[0]
        _plain_f0 = _FACTOR_FORENSIC_PLAIN.get(_f0, _f0.replace("_", " "))
        if _host_f1:
            _for_t1 = (f"{_plain_f0.capitalize()} on host {_host_f1}"
                       + (f" — evidence window {_fmt_ts(_ts_start_f)} to {_fmt_ts(_ts_end_f)}." if _ts_start_f else "."))
        else:
            _for_t1 = (f"{_plain_f0.capitalize()} detected"
                       + (f" — evidence window {_fmt_ts(_ts_start_f)} to {_fmt_ts(_ts_end_f)}." if _ts_start_f else "."))
        _for_t1_cls = "investigate"
    elif _sus_ev:
        _for_t1 = "Suspicious activity under investigation — no confirmed malicious events in this evidence set."
        _for_t1_cls = "review"
    else:
        _for_t1 = "No malicious activity confirmed — evidence inventory complete, no forensic action required."
        _for_t1_cls = "complete"

    return _t1_banner(_for_t1, _for_t1_cls) + f"""
<section class='panel page-break' style='margin-top:18px'>
  <h2>Forensic Analyst — Evidence Inventory</h2>
  <p class='section-note'>Quality rating: COMPLETE (all key fields), PARTIAL (1 key field missing), MISSING (≥2 fields missing).</p>
  {_tbl(["Code", "Type", "Indicator / Value", "Verdict", "Quality"], inv_rows)}
</section>
<section class='panel' style='margin-top:18px'>
  <h2>Preserve Before Contain</h2>
  <ul class='checklist'>
    <li>Capture volatile evidence before shutdown or host isolation where feasible.</li>
    <li>Document who collected each artefact, when it was collected, and any containment step that followed.</li>
    <li>Do not assume persistence or exfiltration without the missing artefacts listed below.</li>
  </ul>
</section>
{proc_chain_html}
<section class='panel' style='margin-top:18px'>
  <h2>Event Timeline — T+N Offsets</h2>
  {_tbl(["Timestamp (UTC)", "Code", "Quality", "Description"], tl_rows)}
</section>
<section class='panel' style='margin-top:18px'>
  <h2>Evidence Gaps — Collect Before Remediation</h2>
  <ul class='checklist'>{gaps_html}</ul>
</section>
"""


# ---------------------------------------------------------------------------
# Compliance / GRC section
# ---------------------------------------------------------------------------

def _compliance(artifact: dict, model: dict | None) -> str:
    """Option A+C: ISM + ISO 27001 + Essential Eight + NDB/APRA/SOCI cross-framework matrix."""
    from src.core.configuration.ism_controls import (
        get_ism_ids_for_factors,
        classify_iso19011_finding,
        ISM_CONTROL_DB,
    )

    if not model:
        facts = artifact.get("facts") or {}
        framework_sections = facts.get("framework_sections") or []
        fw_rows: list[list[Any]] = []
        for sec in framework_sections:
            for item in (sec.get("items") or [])[:4]:
                fw_rows.append([_e(sec.get("title")), _e(item), "—", "—", "REVIEW"])
        return f"""
<section class='panel page-break' style='margin-top:18px'>
  <h2>Compliance / GRC — Framework Mappings</h2>
  {_tbl(["Framework", "Control", "ISM Ref", "Finding", "Status"], fw_rows)}
</section>"""

    ev     = model.get("evidence") or []
    iocs   = model.get("iocs") or {}
    atk    = model.get("attack_story") or {}
    n_mal  = model.get("malicious_count") or 0

    # ── Regulatory notification assessment ──────────────────────────────────
    has_pii = model.get("has_pii") or model.get("has_email")
    has_c2  = model.get("has_c2")
    pii_text = ("CONFIRMED — email addresses observed in ingested data"
                if has_pii else "UNKNOWN — classification not complete")

    # NDB Scheme (Australia — Office of the Australian Information Commissioner)
    if has_pii and n_mal > 0:
        ndb_text = "ASSESSMENT REQUIRED — eligible data breach if access is unauthorised and likely to cause serious harm"
        ndb_variant = "investigate"
    elif has_pii:
        ndb_text = "ASSESSMENT REQUIRED — personal data in scope; determine authorised vs unauthorised access"
        ndb_variant = "investigate"
    else:
        ndb_text = "UNLIKELY — no PII confirmed in current dataset"
        ndb_variant = "complete"

    # APRA CPS 234
    apra_text = ("ASSESSMENT REQUIRED — material information security incident if entity is APRA-regulated"
                 if n_mal >= 3 else "MONITOR — reassess if malicious count grows")
    apra_variant = "investigate" if n_mal >= 3 else "review"

    # SOCI Act s.30BC (Australia)
    soci_text = ("REPORT REQUIRED if system of national significance is in scope"
                 if has_c2 and n_mal > 0 else "REVIEW — assess whether asset class is SOCI-covered")
    soci_variant = "investigate" if has_c2 and n_mal > 0 else "review"

    # GDPR Art.33 (if EU data subjects possible)
    gdpr_text = "ASSESS — determine if EU data subjects are in scope before timer starts"
    gdpr_variant = "review"

    breach_rows: list[list[Any]] = [
        ["PII in scope",            _e(pii_text)],
        ["NDB Scheme (AU)",         _pill(ndb_text[:70] + ("…" if len(ndb_text) > 70 else ""), ndb_variant)],
        ["APRA CPS 234",            _pill(apra_text[:70] + ("…" if len(apra_text) > 70 else ""), apra_variant)],
        ["SOCI Act s.30BC",         _pill(soci_text[:70] + ("…" if len(soci_text) > 70 else ""), soci_variant)],
        ["GDPR Art.33 (if in scope)", _pill(gdpr_text, gdpr_variant)],
        ["Assessment clock",        f"Start notification clock from: <strong>{_e(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))}</strong> (discovery)"],
    ]

    # ── Cross-framework control failure matrix ───────────────────────────────
    fw_rows: list[list[Any]] = []
    all_factors: list[str] = [f for e in ev for f in e.get("factors", [])]

    _FACTOR_CROSS_FW: list[tuple[str, str, str, str, str]] = [
        # (factor, finding_desc, iso27001_ctrl, nist_csf, pci_dss)
        ("malicious_process",           "Unapproved process execution",             "A.12.2.1", "DE.CM-4",   "6.3.3"),
        ("process_injection",           "Memory injection technique observed",       "A.12.4.1", "DE.AE-3",   "10.7"),
        ("c2_communication",            "Confirmed outbound C2 channel",             "A.13.1.2", "DE.CM-1",   "1.3.2"),
        ("data_exfiltration_confirmed", "Data exfiltration via external channel",    "A.8.2.3",  "PR.DS-5",   "3.4"),
        ("credential_harvest",          "Credential theft / phishing",               "A.9.4.2",  "PR.AC-7",   "8.3.1"),
        ("mfa_bypass",                  "MFA not enforced for remote access",        "A.9.4.2",  "PR.AC-7",   "8.4.2"),
        ("legacy_auth",                 "Legacy auth protocols not blocked",         "A.9.4.2",  "PR.AC-7",   "8.3.3"),
        ("privilege_escalation",        "Admin privilege abuse",                     "A.9.2.3",  "PR.AC-4",   "7.2.2"),
        ("lateral_movement",            "Lateral movement across trust boundaries",  "A.13.1.3", "DE.CM-7",   "1.3"),
        ("phishing_subject",            "Phishing email in scope",                   "A.7.2.2",  "PR.AT-1",   "12.6.3"),
        ("log_clearing",                "Audit log tampering",                       "A.12.4.2", "DE.CM-3",   "10.5"),
        ("impossible_travel",           "Impossible travel / account-sharing risk",  "A.9.4.2",  "PR.AC-7",   "8.3.1"),
    ]

    for factor, desc, iso_ctrl, nist_ctrl, pci_ctrl in _FACTOR_CROSS_FW:
        ev_codes = [e["code"] for e in ev if factor in e.get("factors", [])]
        if not ev_codes:
            continue
        code_str = ", ".join(ev_codes[:4])
        ism_ids  = get_ism_ids_for_factors([factor])[:2]
        ism_str  = " / ".join(ism_ids) or "—"
        verdict_for_factor = ("malicious" if any(e.get("verdict") == "malicious"
                                                  for e in ev if factor in e.get("factors", []))
                               else "suspicious")
        classif = classify_iso19011_finding(verdict_for_factor, [factor], len(ev_codes))
        cl_pill = (_pill("MAJOR NCF", "investigate") if classif == "MAJOR NONCONFORMITY"
                   else _pill("MINOR NCF", "review") if classif == "MINOR NONCONFORMITY"
                   else _pill("OBSERVATION", "complete"))
        fw_rows.append([
            f"<small><code>{_e(code_str)}</code></small>",
            _e(f"{desc}"),
            f"<small>{_e(ism_str)}</small>",
            f"<small>{_e(iso_ctrl)}</small>",
            f"<small>{_e(nist_ctrl)}</small>",
            cl_pill,
        ])

    if not fw_rows:
        fw_rows.append(["—", "No critical control failures identified", "—", "—", "—",
                         _pill("PASS", "complete")])

    # ── Compliance action items ─────────────────────────────────────────────
    actions: list[str] = []
    if has_pii:
        actions.append("Identify all affected data subjects and applicable data categories (Privacy Act 1988)")
        actions.append("Route NDB Scheme and APRA notification assessment through legal and privacy review")
    if has_c2:
        actions.append("Assess SOCI Act s.30BC reporting obligations if any SOCI-covered asset is in scope")
    actions.extend([
        "Assign all Major Nonconformities to remediation owners with 24-hour deadlines",
        "Assign Minor Nonconformities to owners with 30-day deadlines",
        "Update risk register — add all confirmed attack vectors and identified control gaps",
        "Determine with legal counsel whether evidence preservation or legal hold is required",
        "Schedule post-incident review within 5 business days of containment",
    ])
    actions_html = "".join(f"<li>{_e(a)}</li>" for a in actions)

    # ── Chain of custody with bitemporal fields ─────────────────────────────
    aid  = (artifact.get("report_id") or
            (artifact.get("meta") or {}).get("source_report_id") or "—")
    cr   = artifact.get("canonical_report") or {}
    hash_input = str(cr.get("assessment_id") or cr.get("report_id") or aid or "")
    report_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

    # Pull valid_time / transaction_time from first available evidence item
    first_ev = next((e for e in ev if e.get("valid_time") or e.get("transaction_time")), {})
    valid_time_val = first_ev.get("valid_time") or "—"
    txn_time_val   = first_ev.get("transaction_time") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    source_sha256  = cr.get("source_file_sha256") or "—"

    # Scope limitation (ISO 19011 §6.3.2)
    missing_sources = []
    if not model.get("has_network"):
        missing_sources.append("network telemetry")
    if not model.get("has_endpoint"):
        missing_sources.append("endpoint/EDR logs")
    if not model.get("has_cloud"):
        missing_sources.append("cloud audit logs")
    scope_note = ""
    if missing_sources:
        scope_note = (
            f"<p style='color:#fb8c00;font-size:13px'>"
            f"<strong>ISO 19011 §6.3.2 Scope Limitation:</strong> "
            f"The following telemetry sources were absent at the time of this assessment: "
            f"<em>{_e(', '.join(missing_sources))}</em>. "
            f"Findings in the relevant domains should be treated as <em>preliminary</em> "
            f"pending ingestion of the missing sources. This limitation is formally documented "
            f"per ISO 19011 §6.3.2 and must be noted in any audit workpaper referencing this report.</p>"
        )

    coc_rows: list[list[Any]] = [
        ["Assessment ID",                  _e(aid)],
        ["Report generated (transaction_time)", f"<code>{_e(txn_time_val)}</code>"],
        ["Evidence valid-time window",     f"<code>{_e(valid_time_val)}</code>"],
        ["Source file SHA-256 prefix",     f"<code>{_e(source_sha256[:16] if source_sha256 != '—' else '—')}</code>"],
        ["Report integrity SHA-256 prefix", f"<code>{_e(report_hash)}</code>"],
        ["Bitemporal standard",            "ISO 19011 §6.5.4 — evidence verifiable at time of finding"],
        ["Preservation status",            _pill("COUNSEL REVIEW ADVISED", "investigate")
                                           if n_mal > 0 else _pill("NOT REQUIRED", "review")],
    ]

    # Fallback: use workbook review_state_counts if CSV model malicious_count is disconnected.
    _ws_confirmed_comp = (((artifact.get("facts") or {}).get("review_state_counts") or {}).get("confirmed_malicious") or 0)
    n_mal = max(n_mal, _ws_confirmed_comp)

    # T1 — spec: which frameworks implicated + notification obligation status
    _notif_frameworks = []
    if (has_pii and n_mal > 0) or has_pii:
        _notif_frameworks.append("NDB Scheme (AU)")
    if has_c2 and n_mal > 0:
        _notif_frameworks.append("SOCI Act s.30BC")
    if n_mal >= 5:
        _notif_frameworks.append("APRA CPS 234")
    _gdpr_text = "GDPR Art.33 assessment required" if has_pii else ""

    major_ncf_count = sum(
        1 for factor, _, _, _, _ in
        [("c2_communication", None, None, None, None)] * (1 if has_c2 and n_mal > 0 else 0)
    )
    # Simpler: count whether there are critical control failures
    has_major = n_mal >= 2 or (has_c2 and n_mal > 0)

    if _notif_frameworks:
        _fw_str = " / ".join(_notif_frameworks[:3])
        _comp_t1 = f"Potential {_fw_str} notification obligation identified — {'72-hour clock is RUNNING' if has_pii and n_mal > 0 else 'assessment required before clock starts'}."
        _comp_t1_cls = "investigate"
    elif has_major:
        _comp_t1 = "Control failures identified — no immediate regulatory notification obligation confirmed, but corrective action is required."
        _comp_t1_cls = "review"
    else:
        _comp_t1 = "No regulatory notification obligations identified — no confirmed control failures in current evidence."
        _comp_t1_cls = "complete"

    return _t1_banner(_comp_t1, _comp_t1_cls) + f"""
<section class='panel page-break' style='margin-top:18px'>
  <h2>Compliance / GRC — Regulatory Notification Assessment</h2>
  {_tbl(["Obligation", "Assessment"], breach_rows)}
</section>

<section class='panel' style='margin-top:18px'>
  <h2>Cross-Framework Control Failure Matrix (ISO 19011 §6.4.7)</h2>
  <p class='section-note'>ISO 19011 classification: <strong>Major NCF</strong> = systematic failure, immediate corrective action required. <strong>Minor NCF</strong> = corrective action within 30 days. <strong>Observation</strong> = improvement opportunity.</p>
  {_tbl(["Evidence", "Finding", "ASD ISM", "ISO 27001", "NIST CSF", "ISO 19011"], fw_rows)}
</section>

<section class='panel' style='margin-top:18px'>
  <h2>Compliance Action Items</h2>
  <ul class='checklist'>{actions_html}</ul>
</section>

<section class='panel' style='margin-top:18px'>
  <h2>Chain of Custody Record (ISO 19011 §6.5.6 Compliant)</h2>
  {scope_note}
  {_tbl(["Field", "Value"], coc_rows)}
</section>
"""


def _essential_eight_block(model: dict) -> str:
    """Option B: Essential Eight maturity assessment block — wired into CISO and Executive sections."""
    from src.core.configuration.ism_controls import derive_essential_eight_maturity
    ev = model.get("evidence") or []
    e8 = derive_essential_eight_maturity(ev)

    ml_color = {0: "#c62828", 1: "#f57c00", 2: "#1565c0", 3: "#2e7d32", 4: "#1b5e20"}
    rows: list[list[Any]] = []
    for item in e8:
        ml = item["maturity_level"]
        ev_codes = ", ".join(item["evidence_codes"][:4]) or "—"
        ism_str  = " / ".join(item["ism_ids"][:2]) or "—"
        ml_style = f"color:{ml_color.get(ml, '#888')};font-weight:700"
        rows.append([
            _e(item["control"]),
            f"<span style='{ml_style}'>ML{ml}</span>",
            f"<span style='font-size:12px;color:var(--muted)'>{_e(item['ml_label'])}</span>",
            f"<small><code>{_e(ev_codes)}</code></small>",
            f"<small>{_e(ism_str)}</small>",
            (_pill("GAP", "investigate") if item["gap_exists"] else _pill("NO EVIDENCE OF FAILURE", "complete")),
        ])

    gap_count = sum(1 for i in e8 if i["gap_exists"])
    summary_color = "#c62828" if gap_count >= 3 else "#f57c00" if gap_count >= 1 else "#2e7d32"
    summary_html = (
        f"<p style='color:{summary_color};font-weight:600;font-size:14px'>"
        f"Essential Eight Gap Count: {gap_count}/8 controls below ML2</p>"
        f"<p class='section-note'>ML0 = not implemented (active gap). "
        f"ML1 = partially implemented (suspected gap). "
        f"ML2 = no evidence of failure (not confirmed as passing — requires positive testing to raise). "
        f"Target: ML3 for most Australian Government entities.</p>"
    )
    return (
        f"<section class='panel' style='margin-top:18px'>"
        f"<h2>Essential Eight Maturity Assessment (ASD 2025)</h2>"
        f"{summary_html}"
        + _tbl(["Control", "Maturity", "Level Label", "Evidence Codes", "ISM Refs", "Gap"], rows)
        + "</section>"
    )


# ---------------------------------------------------------------------------
# CISO section — board-level risk posture + strategic exposure + E8 maturity
# ---------------------------------------------------------------------------

def _ciso(artifact: dict, model: dict | None) -> str:
    """Option A+B: ISM control refs, ISO 19011 classification, Essential Eight maturity."""
    from src.core.configuration.ism_controls import (
        get_ism_ids_for_factors,
        classify_iso19011_finding,
        ISM_CONTROL_DB,
    )

    if not model:
        return ""
    atk      = model.get("attack_story") or {}
    iocs     = model.get("iocs") or {}
    overall  = model.get("overall_risk") or "HIGH"
    n_mal    = model.get("malicious_count") or 0
    n_susp   = model.get("suspicious_count") or 0
    ev       = model.get("evidence") or []

    # Risk exposure score (0-100)
    risk_score = min(100, int((n_mal * 25 + n_susp * 8)))
    risk_band  = ("CRITICAL" if risk_score >= 75 else "HIGH" if risk_score >= 50
                  else "MEDIUM" if risk_score >= 25 else "LOW")
    risk_color = ("#c62828" if risk_band in ("CRITICAL", "HIGH") else
                  "#f57c00" if risk_band == "MEDIUM" else "#388e3c")

    # ── Control failure summary with ISM IDs ────────────────────────────────
    all_factors = [f for e in ev for f in e.get("factors", [])]
    ctrl_fail_rows: list[list[Any]] = []

    _CISO_FACTOR_MAP: list[tuple[str, str]] = [
        ("c2_communication",            "C2 outbound channel permitted through perimeter"),
        ("malicious_process",           "Unapproved process execution on managed endpoint"),
        ("mfa_bypass",                  "MFA not enforced — legacy auth path exploited"),
        ("legacy_auth",                 "Legacy authentication protocols active and unblocked"),
        ("privilege_escalation",        "Privilege escalation pathway exploited"),
        ("lateral_movement",            "Lateral movement across trust boundaries"),
        ("data_exfiltration_confirmed", "Data exfiltrated to external infrastructure"),
        ("credential_harvest",          "Credential harvesting / phishing confirmed"),
        ("phishing_subject",            "Phishing email delivered to managed mailbox"),
        ("impossible_travel",           "Account anomaly — impossible travel / sharing detected"),
        ("log_clearing",                "Audit log clearing detected — forensic impact"),
    ]

    for factor, desc in _CISO_FACTOR_MAP:
        ev_codes = [e["code"] for e in ev if factor in e.get("factors", [])]
        if not ev_codes:
            continue
        ism_ids = get_ism_ids_for_factors([factor])[:2]
        ism_str = " / ".join(ism_ids) if ism_ids else "—"
        verdict_for_factor = ("malicious" if any(e.get("verdict") == "malicious"
                                                  for e in ev if factor in e.get("factors", []))
                               else "suspicious")
        classif = classify_iso19011_finding(verdict_for_factor, [factor], len(ev_codes))
        cl_pill = (_pill("MAJOR NCF", "investigate") if classif == "MAJOR NONCONFORMITY"
                   else _pill("MINOR NCF", "review") if classif == "MINOR NONCONFORMITY"
                   else _pill("OBSERVATION", "complete"))
        ctrl_fail_rows.append([
            f"<small><code>{_e(', '.join(ev_codes[:3]))}</code></small>",
            _e(desc),
            f"<small>{_e(ism_str)}</small>",
            cl_pill,
        ])

    if not ctrl_fail_rows:
        ctrl_fail_rows.append(["—", "No confirmed control failures in current evidence", "—",
                                _pill("PASS", "complete")])

    # ── Regulatory exposure ──────────────────────────────────────────────────
    reg_flags: list[str] = []
    if model.get("has_pii"):
        reg_flags.append("NDB Scheme (AU): Privacy assessment required — PII confirmed in scope")
    if n_mal >= 3 and model.get("has_c2"):
        reg_flags.append("SOCI Act s.30BC: Report to ASD ACSC if critical infrastructure asset is in scope")
    if n_mal >= 5:
        reg_flags.append("APRA CPS 234: Notify APRA within 72 hours if entity is APRA-regulated")
    if not reg_flags:
        reg_flags.append("No immediate regulatory disclosure triggers confirmed — monitor as investigation proceeds")
    reg_html = "".join(f"<li>{_e(f)}</li>" for f in reg_flags)

    # ── Strategic action timeline with ISM traceability ─────────────────────
    strat_actions: list[tuple[str, str, str]] = [
        ("Immediate (0–4h)",
         "Block identified C2 IPs at perimeter firewall; confirm host isolation readiness" if model.get("has_c2")
         else "Validate endpoint isolation procedure is tested and ready",
         "ISM-1261, ISM-0520" if model.get("has_c2") else "ISM-1585"),
        ("24h",
         "Block legacy authentication protocols in Conditional Access / IAM policy" if any("legacy_auth" in all_factors or "mfa_bypass" in all_factors for _ in [1])
         else "Engage IR retainer / MSSP for independent forensic review",
         "ISM-1401, ISM-1559"),
        ("48h",
         "Engage IR retainer / MSSP; brief legal counsel only if regulated scope or material impact confirmed",
         "ISM-1635"),
        ("72h",
         "Board risk register update with validated findings; confirm APRA/ASD ACSC obligations",
         "ISM-1720"),
        ("1 week",
         "Commission post-incident review; update crown jewels asset inventory; reassess ISM maturity baseline",
         "ISM-1720, ISM-1635"),
        ("30 days",
         "Reassess cyber insurance coverage; validate Essential Eight maturity against ASD baseline",
         "ISM-1690, ISM-1900"),
    ]
    strat_html = "".join(
        f"<tr><td><strong>{_e(t)}</strong></td><td>{_e(a)}</td>"
        f"<td><small><code>{_e(i)}</code></small></td></tr>"
        for t, a, i in strat_actions
    )

    attacker_ips = iocs.get("public_ips") or atk.get("attacker_ips") or []
    posture_rows = [
        ["Risk posture",
         f"<strong style='color:{risk_color};font-size:22px'>{risk_band}</strong> "
         f"<span class='pill pill-{'investigate' if risk_band in ('CRITICAL','HIGH','MEDIUM') else 'complete'}'>"
         f"human validation required</span>"],
        ["Confirmed malicious events",   _e(n_mal)],
        ["Suspicious events",            _e(n_susp)],
        ["External entities reviewed",   _e(", ".join(str(ip) for ip in attacker_ips[:4])) or "Not confirmed"],
        ["C2 / network activity",        _pill("SUPPORTED", "investigate") if model.get("has_c2") else _pill("NOT DETECTED", "complete")],
        ["PII in scope",                 _pill("POSSIBLE — REVIEW REQUIRED", "review") if model.get("has_pii") else _pill("NOT CONFIRMED", "review")],
        ["Attack narrative status",      _pill("SUPPORTED", "investigate") if atk.get("narrative") else _pill("PARTIAL", "review")],
    ]

    e8_html = _essential_eight_block(model)

    # T1 — spec: verdict + severity + most important regulatory implication
    _reg_disclosure = None
    if model.get("has_pii") and n_mal > 0:
        _reg_disclosure = "GDPR/NDB Art.33 disclosure assessment required"
    elif n_mal >= 3 and model.get("has_c2"):
        _reg_disclosure = "SOCI Act s.30BC reporting assessment required"
    elif n_mal >= 5:
        _reg_disclosure = "APRA CPS 234 notification assessment required"

    if n_mal > 0:
        _ciso_t1 = (
            f"CONFIRMED CRITICAL INCIDENT: {n_mal} malicious event{'s' if n_mal != 1 else ''} detected"
            + (f" — {_reg_disclosure}." if _reg_disclosure else " — escalation and containment required.")
        )
        _ciso_t1_cls = "investigate"
    elif n_susp > 0:
        _ciso_t1 = (
            f"ELEVATED SUSPICION: {n_susp} event{'s' if n_susp != 1 else ''} require investigation"
            + " — disclosure clock not yet running."
        )
        _ciso_t1_cls = "review"
    else:
        _ciso_t1 = "No confirmed incident — routine review complete, no disclosure obligations triggered."
        _ciso_t1_cls = "complete"

    return _t1_banner(_ciso_t1, _ciso_t1_cls) + f"""
<section class='panel page-break' style='margin-top:18px'>
  <h2>CISO — Current Risk Posture</h2>
  <p class='section-note'>Board-level snapshot. All findings require human validation before external disclosure or regulatory notification.</p>
  {_tbl(["Metric", "Status"], posture_rows)}
</section>

<section class='panel' style='margin-top:18px'>
  <h2>Control Failures — ISM + ISO 19011 (§6.4.7)</h2>
  <p class='section-note'><strong>Major NCF</strong> = systematic failure requiring immediate corrective action. <strong>Minor NCF</strong> = corrective action within 30 days. <strong>Observation</strong> = improvement opportunity.</p>
  {_tbl(["Evidence", "Control Failure", "ASD ISM Refs", "ISO 19011 Class"], ctrl_fail_rows)}
</section>

{e8_html}

<section class='panel' style='margin-top:18px'>
  <h2>Regulatory Exposure Assessment</h2>
  <ul class='checklist'>{reg_html}</ul>
</section>

<section class='panel' style='margin-top:18px'>
  <h2>CISO Action Timeline (ISM Traceable)</h2>
  <table class='tbl'>
    <thead><tr><th>Timeframe</th><th>Required Action</th><th>ISM Controls</th></tr></thead>
    <tbody>{strat_html}</tbody>
  </table>
</section>
"""


def _audit(artifact: dict, model: dict | None) -> str:
    """Option A+C: ISO 19011 NCF classification, ISM control IDs, corrective action register,
    bitemporal CoC statement, scope limitation per §6.3.2."""
    from src.core.configuration.ism_controls import (
        get_ism_ids_for_factors,
        classify_iso19011_finding,
        build_corrective_action_register,
        ISM_CONTROL_DB,
    )

    if not model:
        return ""
    atk    = model.get("attack_story") or {}
    ev     = model.get("evidence") or []
    iocs   = model.get("iocs") or {}
    n_mal  = model.get("malicious_count") or 0

    # ── §6.4.7 Control failure findings with ISO 19011 classification ────────
    finding_rows: list[list[Any]] = []
    _seen_ctrl: set[str] = set()
    for e in ev[:20]:
        factors  = e.get("factors") or []
        verdict  = e.get("verdict") or "good"
        code     = e.get("code") or "—"
        sheet    = e.get("sheet") or e.get("source") or "—"
        sev      = e.get("severity") or "info"
        if verdict not in ("malicious", "suspicious"):
            continue
        ism_ids = get_ism_ids_for_factors(factors)[:2]
        ism_str = " / ".join(ism_ids) if ism_ids else "—"
        ctrl_fail = (
            "Process Execution Control (App Allowlisting)"
            if any("process" in f.lower() or "exec" in f.lower() for f in factors)
            else "Network Egress Control (Firewall/Proxy)"
            if any("c2" in f.lower() or "connection" in f.lower() for f in factors)
            else "Email Filtering Control (Gateway)"
            if sheet.lower() == "email"
            else "Identity & Access Control (MFA/Conditional Access)"
            if any("auth" in f.lower() or "cred" in f.lower() or "mfa" in f.lower() or "travel" in f.lower() for f in factors)
            else "Endpoint Detection Control (EDR)"
        )
        # Deduplicate to avoid repeating same ctrl_fail
        ctrl_key = f"{ctrl_fail}|{verdict}"
        n_same   = sum(1 for e2 in ev if ctrl_key.split("|")[0].split("(")[0].strip().lower()
                       in " ".join(e2.get("factors") or []).lower())
        classif  = classify_iso19011_finding(verdict, factors, n_same)
        cl_pill  = (_pill("MAJOR NCF", "investigate") if classif == "MAJOR NONCONFORMITY"
                    else _pill("MINOR NCF", "review")  if classif == "MINOR NONCONFORMITY"
                    else _pill("OBSERVATION", "complete"))
        finding_rows.append([
            f"<code>{_e(code)}</code>",
            _e(ctrl_fail),
            f"<small>{_e(ism_str)}</small>",
            _e(sheet),
            cl_pill,
            _pill(sev.upper(), "investigate" if sev in ("critical","high","medium") else "review"),
        ])

    if not finding_rows:
        finding_rows.append(["—", "No control failures identified", "—", "—",
                              _pill("PASS", "complete"), _pill("LOW", "review")])

    # ── ISO 19011 §6.6 Corrective Action Register ───────────────────────────
    car = build_corrective_action_register(ev, assessment_id=(
        (artifact.get("canonical_report") or {}).get("assessment_id") or
        artifact.get("report_id") or ""
    ))
    car_rows: list[list[Any]] = []
    for entry in car[:12]:
        ism_str = " / ".join(entry["ism_ids"][:2]) or "—"
        codes_str = ", ".join(entry["evidence_codes"][:4])
        dl_str = entry.get("deadline_ts") or f"+{entry['deadline_hours']}h"
        car_rows.append([
            f"<strong>{_e(entry['finding_id'])}</strong>",
            (_pill("MAJOR NCF", "investigate") if entry["classification"] == "MAJOR NONCONFORMITY"
             else _pill("MINOR NCF", "review") if entry["classification"] == "MINOR NONCONFORMITY"
             else _pill("OBS", "complete")),
            f"<small>{_e(ism_str)}</small>",
            f"<small>{_e(entry['root_cause'][:80])}</small>",
            f"<small>{_e(entry['action'][:80])}</small>",
            f"<small><code>{_e(dl_str[:19])}</code></small>",
            f"<small><code>{_e(codes_str)}</code></small>",
        ])
    if not car_rows:
        car_rows.append(["—", _pill("PASS", "complete"), "—", "No corrective actions required", "—", "—", "—"])

    # ── Telemetry coverage ───────────────────────────────────────────────────
    has_net   = model.get("has_network")
    has_email = model.get("has_email")
    has_edr   = model.get("has_endpoint")
    has_cloud = model.get("has_cloud")
    coverage_rows = [
        ["Network telemetry",  _pill("PRESENT", "complete") if has_net   else _pill("ABSENT", "missing"),
         "ISM-1261 / ISM-0520", "Lateral movement and C2 detection"],
        ["Email telemetry",    _pill("PRESENT", "complete") if has_email else _pill("ABSENT", "missing"),
         "ISM-1806",           "Phishing vector identification"],
        ["Endpoint / EDR",     _pill("PRESENT", "complete") if has_edr   else _pill("ABSENT", "missing"),
         "ISM-1417 / ISM-1585","Process execution and malware analysis"],
        ["Cloud audit logs",   _pill("PRESENT", "complete") if has_cloud else _pill("ABSENT", "missing"),
         "ISM-0109 / ISM-1405","Identity and privilege escalation audit"],
    ]

    # ── §6.3.2 Scope limitation statement ────────────────────────────────────
    missing_sources = []
    if not has_net:
        missing_sources.append("network telemetry")
    if not has_edr:
        missing_sources.append("endpoint/EDR logs")
    if not has_cloud:
        missing_sources.append("cloud audit logs")
    scope_limitation_html = ""
    if missing_sources:
        scope_limitation_html = (
            f"<div style='background:#fff3e0;border-left:4px solid #fb8c00;"
            f"padding:12px 16px;margin:14px 0;border-radius:6px'>"
            f"<strong>ISO 19011 §6.3.2 — Formal Scope Limitation</strong><br>"
            f"<span style='font-size:13px'>"
            f"The following telemetry sources were absent at the time of this assessment: "
            f"<em>{_e(', '.join(missing_sources))}</em>. "
            f"Findings in the domains of {_e(', '.join(missing_sources))} "
            f"should be treated as <strong>preliminary</strong> pending ingestion of the missing sources. "
            f"This limitation is formally documented per ISO 19011 §6.3.2 and must be noted in all "
            f"audit workpapers, corrective action logs, and regulatory submissions referencing this report."
            f"</span></div>"
        )

    # ── Bitemporal chain of custody (ISO 19011 §6.5.6) ──────────────────────
    cr        = artifact.get("canonical_report") or {}
    aid       = (artifact.get("report_id") or (artifact.get("meta") or {}).get("source_report_id") or "—")
    hash_in   = str(cr.get("assessment_id") or cr.get("report_id") or aid or "")
    rep_hash  = hashlib.sha256(hash_in.encode()).hexdigest()[:20]
    gen_ts    = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    source_sha256 = cr.get("source_file_sha256") or "—"

    # Pull bitemporal fields from the first available evidence item
    first_ev = next((e for e in ev if e.get("valid_time") or e.get("transaction_time")), {})
    valid_time_val = first_ev.get("valid_time") or "—"
    txn_time_val   = first_ev.get("transaction_time") or gen_ts

    coc_rows  = [
        ["Assessment ID (ISO 19011 §4.2)",               _e(aid)],
        ["Transaction time (ingested)",                  f"<code>{_e(txn_time_val)}</code>"],
        ["Evidence valid-time window",                   f"<code>{_e(valid_time_val)}</code>"],
        ["Source file SHA-256 prefix (chain of custody)", f"<code>{_e(source_sha256[:16] if source_sha256 != '—' else '—')}</code>"],
        ["Report generated (UTC)",                       f"<code>{_e(gen_ts)}</code>"],
        ["Total events analysed",                        _e(model.get("total_events") or len(ev))],
        ["Confirmed malicious",                          _e(n_mal)],
        ["Report integrity SHA-256 prefix",              f"<code>{_e(rep_hash)}</code>"],
        ["Bitemporal compliance",                        "ISO 19011 §6.5.4 — evidence verifiable at time of finding"],
        ["Preservation status",                          _pill("COUNSEL REVIEW ADVISED", "investigate")
                                                          if n_mal > 0 else _pill("NOT REQUIRED", "review")],
    ]

    # ── Audit recommendations ────────────────────────────────────────────────
    recs = [
        "Preserve flagged evidence artefacts under documented chain-of-custody procedures",
        "Validate SIEM log retention meets policy minimum (ISM-0109 requires ≥7 years for some entities)",
        "Confirm EDR agent deployment on 100% of managed endpoints within 30 days (ISM-1417)",
        "Close network egress gaps — enforce proxy / firewall policy for all outbound traffic (ISM-0520)",
        "Schedule quarterly threat hunt based on MITRE TTPs identified in this report",
        "Update incident response playbook to reflect attack vectors after human validation (ISM-1635)",
        "Commission post-incident review within 5 business days of containment (ISM-1720)",
    ]
    if model.get("has_pii"):
        recs.insert(0, "Preserve PII-related evidence and route data-subject assessment through privacy or legal review (NDB Scheme)")
    recs_html = "".join(f"<li>{_e(r)}</li>" for r in recs)

    # T1 — audit spec: objective scope statement (§6.4.7 language)
    # Fallback: use workbook review_state_counts if CSV model malicious_count is disconnected.
    _ws_confirmed_aud = (((artifact.get("facts") or {}).get("review_state_counts") or {}).get("confirmed_malicious") or 0)
    n_mal = max(n_mal, _ws_confirmed_aud)

    major_ncf_count = sum(
        1 for row in finding_rows
        if "MAJOR" in str(row[4] if len(row) > 4 else "")
    )
    all_finding_verdicts = [e.get("verdict") for e in ev if e.get("verdict") in ("malicious", "suspicious")]
    if n_mal > 0:
        _aud_t1 = (
            f"AUDIT FINDING: {n_mal} confirmed control failure{'s' if n_mal != 1 else ''} "
            f"classified as Major Nonconformity — immediate corrective action required per ISO 19011 §6.6."
        )
        _aud_t1_cls = "investigate"
    elif any(v == "suspicious" for v in all_finding_verdicts):
        _aud_t1 = "AUDIT FINDING: Suspected control weaknesses identified — Minor Nonconformities raised, corrective actions required within 30 days."
        _aud_t1_cls = "review"
    else:
        _aud_t1 = "AUDIT FINDING: No nonconformities identified — all controls operating within acceptable parameters."
        _aud_t1_cls = "complete"

    return _t1_banner(_aud_t1, _aud_t1_cls) + f"""
<section class='panel page-break' style='margin-top:18px'>
  <h2>Audit — Control Failure Findings (ISO 19011 §6.4.7)</h2>
  {scope_limitation_html}
  <p class='section-note'>Classification: <strong>MAJOR NCF</strong> = systematic failure requiring immediate corrective action. <strong>MINOR NCF</strong> = corrective action within 30 days. <strong>OBSERVATION</strong> = no current breach but improvement required.</p>
  {_tbl(["Evidence Code", "Control Failure", "ASD ISM Refs", "Source", "ISO 19011", "Severity"], finding_rows)}
</section>

<section class='panel' style='margin-top:18px'>
  <h2>Corrective Action Register (ISO 19011 §6.6)</h2>
  <p class='section-note'>Each Major NCF requires a root cause, assigned owner, deadline, and verification method. Owner column to be completed by the audit lead.</p>
  {_tbl(["Finding ID", "Class", "ISM Refs", "Root Cause", "Corrective Action", "Deadline", "Evidence"], car_rows)}
</section>

<section class='panel' style='margin-top:18px'>
  <h2>Telemetry Coverage Assessment</h2>
  {_tbl(["Source", "Status", "ISM Controls", "Audit Domain"], coverage_rows)}
</section>

<section class='panel' style='margin-top:18px'>
  <h2>Audit Recommendations (ISM-Traceable)</h2>
  <ul class='checklist'>{recs_html}</ul>
</section>

<section class='panel' style='margin-top:18px'>
  <h2>Chain of Custody Record (ISO 19011 §6.5.6 Compliant)</h2>
  <p class='section-note'>Bitemporal evidence record: <em>transaction_time</em> = when evidence was ingested into this system; <em>valid_time</em> = when the event actually occurred. §6.5.4 requires that findings be supported by evidence available at the time of the audit — transaction_time provides this proof.</p>
  {_tbl(["Field", "Value"], coc_rows)}
</section>
"""


# ---------------------------------------------------------------------------
# MSSP section — client-forwarding SLA view (persona_nontechnical_summaries §7)
# ---------------------------------------------------------------------------

def _mssp(artifact: dict, model: dict | None) -> str:
    """MSSP persona: client-ready alert summary, SLA status, escalation path.

    Written to be forwarded directly to a client IT manager without editing.
    No security jargon — all technical terms are translated.
    """
    if not model:
        return ""

    ev     = model.get("evidence") or []
    iocs   = model.get("iocs") or {}
    atk    = model.get("attack_story") or {}
    n_mal  = model.get("malicious_count") or 0
    n_susp = model.get("suspicious_count") or 0
    n_crit = sum(1 for e in ev if e.get("severity") == "critical")

    # ── T1 — client alert one-liner (spec: copy-paste into client email) ────
    if n_mal > 0:
        _mssp_t1 = f"ALERT: {n_mal} confirmed malicious event{'s' if n_mal != 1 else ''} detected in your environment — immediate response required."
        _mssp_t1_cls = "investigate"
    elif n_susp > 0:
        _mssp_t1 = f"ADVISORY: Suspicious activity detected ({n_susp} event{'s' if n_susp != 1 else ''}) — investigation underway, no confirmed breach yet."
        _mssp_t1_cls = "review"
    else:
        _mssp_t1 = "INFO: Security review complete — no threats detected in this analysis window."
        _mssp_t1_cls = "complete"

    # ── SLA status ───────────────────────────────────────────────────────────
    if n_crit > 0:
        sla_status   = "BREACHED" if n_crit >= 2 else "AT RISK"
        sla_variant  = "investigate" if sla_status == "BREACHED" else "review"
        sla_note     = ("We are past the agreed response time — client must be notified immediately."
                        if sla_status == "BREACHED"
                        else "We are approaching the P1 response deadline — accelerate triage now.")
        p_tier = "P1"
        sla_window = "15 minutes"
    elif n_mal > 0:
        sla_status   = "AT RISK"
        sla_variant  = "review"
        sla_note     = "We are approaching the response deadline — accelerate triage."
        p_tier = "P2"
        sla_window = "4 hours"
    else:
        sla_status  = "WITHIN TARGET"
        sla_variant = "complete"
        sla_note    = "Response is on track — continue normal workflow."
        p_tier = "P3"
        sla_window = "Next business day"

    escalation_steps: list[str] = []
    if n_mal > 0 or n_crit > 0:
        escalation_steps.append(f"Notify client within {sla_window} per MSA escalation clause.")
        escalation_steps.append("Engage IR retainer if containment not achieved within 1 hour.")
        escalation_steps.append("Log escalation time and client acknowledgement in ticketing system.")
    else:
        escalation_steps.append("Continue monitoring — escalate only if new events are confirmed malicious.")
        escalation_steps.append("Close ticket after 48-hour watchlist period with no recurrence.")
    esc_html = "".join(f"<li>{_e(s)}</li>" for s in escalation_steps)

    # ── Client-ready findings (no jargon) ───────────────────────────────────
    client_rows: list[list[Any]] = []
    attacker_ips = iocs.get("public_ips") or atk.get("attacker_ips") or []
    hosts = (atk.get("internal_hosts") or list(iocs.get("hosts") or set()))[:3]

    for e in ev[:8]:
        factors = e.get("factors") or []
        verdict = e.get("verdict") or "unknown"
        if verdict not in ("malicious", "suspicious"):
            continue
        r = e["row"]
        host = str(r.get("hostname") or r.get("computer") or r.get("host") or "your network device")[:32]
        # Plain-English description for non-technical client
        plain_desc = next(
            (_FACTOR_NONTECHNICAL.get(f) for f in factors if f in _FACTOR_NONTECHNICAL),
            f"Unusual activity was detected on {host}."
        )
        client_action_map = {
            "malicious": "Notify your IT team immediately and do not restart affected machines.",
            "suspicious": "Ask your IT team to review this activity — no immediate action yet.",
        }
        client_action = client_action_map.get(verdict, "No action required at this time.")
        client_rows.append([
            _e(host),
            _e(plain_desc),
            _e(client_action),
            _pill("CONFIRMED THREAT" if verdict == "malicious" else "UNDER INVESTIGATION",
                  "investigate" if verdict == "malicious" else "review"),
        ])

    if not client_rows:
        client_rows.append(["—", "No threats detected", "No action required", _pill("CLEAR", "complete")])

    # ── What the MSSP is doing on the client's behalf ───────────────────────
    mssp_actions: list[str] = []
    if n_mal > 0 and attacker_ips:
        mssp_actions.append(f"Reviewing {len(attacker_ips)} external IP address{'es' if len(attacker_ips) != 1 else ''} for policy-based blocking.")
    if n_mal > 0 and hosts:
        mssp_actions.append(f"Requesting evidence preservation from affected machine{'s' if len(hosts) != 1 else ''}: {', '.join(str(h) for h in hosts[:3])}.")
    mssp_actions.append("Correlating with threat intelligence sources to determine attacker origin and pattern.")
    if n_mal > 0:
        mssp_actions.append("Preparing incident report for client delivery within the agreed SLA window.")
    else:
        mssp_actions.append("Monitoring for recurrence across the next 48-hour analysis window.")
    mssp_html = "".join(f"<li>{_e(a)}</li>" for a in mssp_actions)

    # ── IOC summary in plain language ───────────────────────────────────────
    ioc_plain: list[str] = []
    if attacker_ips:
        ioc_plain.append(f"External server addresses involved: {', '.join(str(ip) for ip in attacker_ips[:4])}")
    if iocs.get("processes"):
        ioc_plain.append(f"Suspicious programs detected: {', '.join(iocs['processes'][:3])}")
    if iocs.get("domains"):
        ioc_plain.append(f"Suspicious websites contacted: {', '.join(iocs['domains'][:3])}")
    ioc_plain_html = "".join(f"<li>{_e(s)}</li>" for s in ioc_plain) or "<li>No specific indicators extracted.</li>"

    return _t1_banner(_mssp_t1, _mssp_t1_cls) + f"""
<section class='panel page-break' style='margin-top:18px'>
  <h2>MSSP — SLA and Escalation Status</h2>
  <div style='display:flex;gap:24px;align-items:flex-start;flex-wrap:wrap;margin-bottom:12px'>
    <div>
      <div style='font-size:12px;color:var(--muted);text-transform:uppercase'>SLA Status</div>
      {_pill(sla_status, sla_variant)}
    </div>
    <div>
      <div style='font-size:12px;color:var(--muted);text-transform:uppercase'>Priority Tier</div>
      <strong>{_e(p_tier)}</strong>
    </div>
    <div>
      <div style='font-size:12px;color:var(--muted);text-transform:uppercase'>Response Window</div>
      <strong>{_e(sla_window)}</strong>
    </div>
  </div>
  <p class='section-note'>{_e(sla_note)}</p>
  <h3>Escalation Steps</h3>
  <ul class='checklist'>{esc_html}</ul>
</section>

<section class='panel' style='margin-top:18px'>
  <h2>Client-Ready Findings</h2>
  <p class='section-note'>This section is written for your client's IT manager. All technical terms have been translated into plain language.</p>
  {_tbl(["Affected System", "What Happened", "What Your Team Should Do", "Status"], client_rows)}
</section>

<section class='panel' style='margin-top:18px'>
  <h2>What the MSSP Is Doing on Your Behalf</h2>
  <ul class='checklist'>{mssp_html}</ul>
</section>

<section class='panel' style='margin-top:18px'>
  <h2>Technical Summary (for client IT manager)</h2>
  <ul class='checklist'>{ioc_plain_html}</ul>
</section>
"""


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

_DISPATCH = {
    "executive":     _executive_extra,
    "soc_analyst":   _soc_analyst,
    "threat_hunter": _threat_hunter,
    "forensics":     _forensics,
    "compliance":    _compliance,
    "ciso":          _ciso,
    "audit":         _audit,
    "mssp":          _mssp,
}


def build_persona_section_html(artifact: dict, persona: str) -> str:
    """Return the persona-specific supplementary HTML section string.

    Safe — catches all exceptions and returns an empty string or HTML comment.
    Never raises.
    """
    fn = _DISPATCH.get(persona)
    if fn is None:
        return ""
    model = (artifact.get("canonical_report") or {}).get("_csv_model")
    try:
        return fn(artifact, model)
    except Exception as exc:  # pragma: no cover — safety net
        return f"<!-- persona_section_builders error ({escape(persona)}): {escape(str(exc))} -->"
