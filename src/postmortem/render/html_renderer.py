"""
HTML Renderer — Postmortem in-tab view
=======================================

Renders the assembled PostmortemDocument as a single HTML fragment for
display inside the Postmortem tab on breach.html.

Stateless. Reads the document, calls ``get_computed_section()`` for each
section so human edits are reflected, and emits semantic HTML with hooks
for the JS layer to attach edit handlers.

The JS layer (``static/js/breach_postmortem.js``) handles interactions:
  - Click an edit pencil → modal with field path + new value form
  - Click sign-off → POST /sections/{id}/sign-off
  - Click "Push to Jira" → POST /push-itsm
  - Click "Pre-fill regulator form" → POST /regulator-form
"""
from __future__ import annotations

import html
import json
from typing import Any


def render_postmortem_html(document: dict) -> str:
    """Return the full HTML fragment for the Postmortem tab."""
    from src.postmortem.postmortem_assembler import (
        get_computed_section, signoff_summary,
    )

    pm_id = document.get("postmortem_id", "?")
    cluster_id = document.get("cluster_id", "?")
    verdict = document.get("verdict") or {}
    summary = signoff_summary(document)
    data_quality = document.get("data_quality") or {}

    parts: list[str] = []
    parts.append('<div class="postmortem-root" data-postmortem-id="%s">'
                 % _esc(pm_id))

    # Header
    parts.append(_render_header(document, summary))

    # Data quality issues banner
    issues = data_quality.get("issues") or []
    if issues:
        parts.append(_render_data_quality_banner(issues))

    # Verdict block
    parts.append(_render_verdict_block(verdict))

    # Sections
    section_titles = [
        ("s1_incident_lifecycle",     "1. Incident Lifecycle (ISO 27035)"),
        ("s2_threat_reconstruction",  "2. Threat Reconstruction (MITRE + STRIDE)"),
        ("s3_control_failures",       "3. Control Failures by Framework"),
        ("s4_sabsa_architecture",     "4. SABSA Architecture & Policy Implications"),
        ("s5_risk_register_delta",    "5. Risk Register Delta"),
        ("s6_regulatory_clocks",      "6. Regulatory Notification Clocks"),
        ("s7_corrective_actions",     "7. Corrective Actions"),
    ]
    for sec_id, title in section_titles:
        section = next((s for s in (document.get("sections") or [])
                        if s.get("section_id") == sec_id), None)
        if not section:
            continue
        computed = get_computed_section(document, sec_id)
        parts.append(_render_section(sec_id, title, section, computed))

    # Footer with actions
    parts.append(_render_actions_footer(document))
    parts.append('</div>')
    return "\n".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
#  Header / verdict / data quality
# ─────────────────────────────────────────────────────────────────────────────


def _render_header(document: dict, summary: dict) -> str:
    pm_id = document.get("postmortem_id", "?")
    cluster_id = document.get("cluster_id", "?")
    tx_time = document.get("transaction_time", "?")
    return f'''
<div class="postmortem-header">
  <div class="pm-id"><strong>Postmortem:</strong> {_esc(pm_id)}</div>
  <div class="pm-cluster">Cluster: {_esc(cluster_id)}</div>
  <div class="pm-time">Assembled: {_esc(tx_time)}</div>
  <div class="pm-signoff-summary">
    <span class="pm-signed">{summary["signed"]} signed</span>
    /
    <span class="pm-pending">{summary["pending"]} pending</span>
    /
    <span class="pm-stubs">{summary["stubs"]} v2 stubs</span>
  </div>
</div>'''


def _render_verdict_block(verdict: dict) -> str:
    pv = verdict.get("platform_verdict", "?")
    confidence = verdict.get("confidence", 0.0)
    materiality = verdict.get("materiality_assessment", "?")
    rationale = verdict.get("materiality_rationale", "")
    notif_status = verdict.get("notification_status", "?")
    return f'''
<div class="pm-verdict-block pm-verdict-{_esc(pv.lower())}">
  <h3>Verdict</h3>
  <div><strong>Platform verdict:</strong> {_esc(pv)} (confidence {confidence:.2f})</div>
  <div><strong>Materiality:</strong> {_esc(materiality)}</div>
  <div><strong>Rationale:</strong> {_esc(rationale)}</div>
  <div><strong>Notification status:</strong> {_esc(notif_status)}</div>
</div>'''


def _render_data_quality_banner(issues: list[dict]) -> str:
    items = []
    for i in issues:
        sev = i.get("severity", "warning")
        msg = i.get("message", "")
        code = i.get("code", "")
        items.append(f'<li class="dq-{_esc(sev)}"><code>{_esc(code)}</code> {_esc(msg)}</li>')
    return f'''
<div class="pm-data-quality-banner">
  <h4>⚠ Data quality issues</h4>
  <ul>{"".join(items)}</ul>
</div>'''


# ─────────────────────────────────────────────────────────────────────────────
#  Section rendering
# ─────────────────────────────────────────────────────────────────────────────


def _render_section(sec_id: str, title: str, section: dict, computed: Any) -> str:
    v1_status = section.get("v1_status", "")
    signoff = section.get("signoff")
    signed_class = "pm-signed" if signoff else "pm-unsigned"
    stub_badge = ('<span class="pm-stub-badge">v2 stub — placeholder</span>'
                  if v1_status == "STUB" else '')
    error_badge = ('<span class="pm-error-badge">build error</span>'
                   if section.get("build_error") else '')

    body_html = _render_section_body(sec_id, computed, section)

    signoff_html = (
        f'<div class="pm-signoff-record">Signed by {_esc(signoff["signed_by"])} '
        f'at {_esc(signoff["signed_at"])}</div>'
        if signoff else
        f'<button class="pm-signoff-btn" data-section-id="{_esc(sec_id)}">Sign off</button>'
    )

    overrides_count = len(section.get("overrides") or [])
    overrides_badge = (f'<span class="pm-overrides-count">{overrides_count} edit(s)</span>'
                       if overrides_count else '')

    return f'''
<section class="pm-section {signed_class}" data-section-id="{_esc(sec_id)}">
  <header>
    <h2>{_esc(title)} {stub_badge}{error_badge}</h2>
    {overrides_badge}
  </header>
  <div class="pm-section-body">{body_html}</div>
  <footer class="pm-section-footer">
    <button class="pm-edit-btn" data-section-id="{_esc(sec_id)}">Edit field</button>
    {signoff_html}
  </footer>
</section>'''


def _render_section_body(sec_id: str, computed: Any, section: dict) -> str:
    """Per-section pretty rendering. Falls back to JSON pre block for stubs
    and build errors."""
    if computed is None:
        return '<p class="pm-empty">(no auto output — section is a v2 stub)</p>'

    if section.get("build_error"):
        err = section["build_error"]
        return (f'<div class="pm-build-error">'
                f'<strong>Section build error:</strong> {_esc(err.get("exception_class","?"))} '
                f'— {_esc(err.get("message",""))}</div>')

    if sec_id == "s1_incident_lifecycle":
        return _render_s1(computed)
    if sec_id == "s3_control_failures":
        return _render_s3(computed)
    if sec_id == "s6_regulatory_clocks":
        return _render_s6(computed)
    if sec_id == "s7_corrective_actions":
        return _render_s7(computed)

    # Stubs and other sections: pretty JSON
    return f'<pre class="pm-json">{_esc(_pretty(computed))}</pre>'


def _render_s1(computed: dict) -> str:
    detect = computed.get("detect") or {}
    timeline = computed.get("timeline") or []
    contain = computed.get("contain") or {}
    pir = computed.get("post_incident_review") or {}

    parts = ['<h4>Detect</h4>']
    parts.append('<ul>')
    parts.append(f'<li>Method: {_esc(detect.get("method","?"))}</li>')
    parts.append(f'<li>Reference: {_esc(detect.get("reference",""))}</li>')
    parts.append(f'<li>Discovered: {_esc(detect.get("detected_at",""))}</li>')
    parts.append(f'<li>First evidence: {_esc(detect.get("first_evidence_at",""))}</li>')
    parts.append(f'<li>Detection lag: {_esc(detect.get("detection_lag_human",""))}</li>')
    parts.append(f'<li>Channel: {_esc(detect.get("discovery_channel",""))}</li>')
    parts.append('</ul>')

    parts.append('<h4>Timeline</h4>')
    if timeline:
        parts.append('<table class="pm-table"><thead><tr><th>Time</th><th>Phase</th><th>Event</th><th>Refs</th></tr></thead><tbody>')
        for t in timeline:
            refs = ", ".join(str(r) for r in (t.get("evidence_refs") or []))
            parts.append(f'<tr><td>{_esc(t.get("ts",""))}</td>'
                         f'<td>{_esc(t.get("phase","") or "-")}</td>'
                         f'<td>{_esc(t.get("event",""))}</td>'
                         f'<td>{_esc(refs)}</td></tr>')
        parts.append('</tbody></table>')
    else:
        parts.append('<p class="pm-empty">(timeline empty)</p>')

    parts.append('<h4>Contain / Eradicate / Recover</h4>')
    parts.append('<p class="pm-todo">Analyst fills in via the Edit field button. '
                 'Platform does not infer containment actions.</p>')

    parts.append('<h4>Post-Incident Review</h4>')
    rc = pir.get("root_cause")
    parts.append(f'<div>Root cause: {_esc(rc) if rc else "<em>(pending analyst entry)</em>"}</div>')

    return "".join(parts)


def _render_s3(computed: dict) -> str:
    summary = computed.get("summary") or {}
    flat_list = computed.get("flat_list") or []
    asks = computed.get("auditor_asks") or []

    parts = []
    parts.append(f'<div class="pm-summary-stats">')
    parts.append(f'<span><strong>{summary.get("failed_control_count",0)}</strong> failed controls</span>')
    parts.append(f'<span><strong>{summary.get("critical_control_count",0)}</strong> critical</span>')
    parts.append(f'<span>across <strong>{summary.get("framework_count",0)}</strong> frameworks</span>')
    parts.append(f'</div>')

    if flat_list:
        parts.append('<table class="pm-table">')
        parts.append('<thead><tr><th>Severity</th><th>Framework</th><th>Control</th>'
                     '<th>Failure</th><th>Triggered by</th><th>Evidence</th></tr></thead><tbody>')
        for r in flat_list:
            tb = ", ".join(r.get("triggered_by") or [])
            er = ", ".join(str(x) for x in (r.get("evidence_refs") or []))
            parts.append(f'<tr class="sev-{_esc(r.get("severity",""))}">')
            parts.append(f'<td>{_esc(r.get("severity",""))}</td>')
            parts.append(f'<td>{_esc(r.get("framework",""))}</td>')
            parts.append(f'<td>{_esc(r.get("control_id",""))} — {_esc(r.get("control_name",""))}</td>')
            parts.append(f'<td>{_esc(r.get("failure_type",""))}</td>')
            parts.append(f'<td>{_esc(tb)}</td>')
            parts.append(f'<td>{_esc(er)}</td>')
            parts.append(f'</tr>')
        parts.append('</tbody></table>')
    else:
        parts.append('<p class="pm-empty">(no control failures recorded — '
                     'check upstream mitre_techniques)</p>')

    if asks:
        parts.append('<h4>Likely auditor questions</h4><ul>')
        for q in asks:
            parts.append(f'<li>{_esc(q)}</li>')
        parts.append('</ul>')

    return "".join(parts)


def _render_s6(computed: dict) -> str:
    summary = computed.get("summary") or {}
    triggers = computed.get("triggers") or []

    parts = []
    parts.append(f'<div class="pm-warning-banner">'
                 f'⚠ {_esc(computed.get("human_submit_only_notice",""))}</div>')

    if not triggers:
        return '<p class="pm-empty">No regulatory triggers fired.</p>'

    parts.append(f'<div><strong>Tightest deadline:</strong> '
                 f'{_esc(summary.get("tightest_deadline",""))} '
                 f'({summary.get("tightest_hours_left","?")}h remaining)</div>')

    parts.append('<table class="pm-table"><thead><tr>'
                 '<th>Regulator</th><th>Clock</th><th>Deadline</th><th>Hours left</th>'
                 '<th>Rationale</th><th>Action</th></tr></thead><tbody>')
    for t in triggers:
        overdue_class = "overdue" if t.get("overdue") else ""
        prefill_btn = (f'<button class="pm-prefill-btn" data-regulator="{_esc(t.get("trigger_id",""))}">'
                       f'Pre-fill form</button>'
                       if t.get("form_module") else '')
        parts.append(f'<tr class="{overdue_class}">')
        parts.append(f'<td>{_esc(t.get("regulator",""))} ({_esc(t.get("name",""))})</td>')
        parts.append(f'<td>{_esc(t.get("clock_human",""))}</td>')
        parts.append(f'<td>{_esc(t.get("deadline",""))}</td>')
        parts.append(f'<td>{t.get("hours_remaining","?")}</td>')
        parts.append(f'<td>{_esc(t.get("rationale",""))}</td>')
        parts.append(f'<td>{prefill_btn}</td>')
        parts.append(f'</tr>')
    parts.append('</tbody></table>')
    return "".join(parts)


def _render_s7(computed: dict) -> str:
    actions = computed.get("actions") or []
    if not actions:
        return '<p class="pm-empty">(no corrective actions)</p>'

    parts = ['<table class="pm-table"><thead><tr>'
             '<th>Priority</th><th>Title</th><th>Owner role</th>'
             '<th>Due (days)</th><th>Frameworks</th></tr></thead><tbody>']
    for a in actions:
        fw = ", ".join(a.get("framework_refs") or [])
        parts.append(f'<tr class="pri-{_esc(a.get("priority","").lower())}">')
        parts.append(f'<td>{_esc(a.get("priority",""))}</td>')
        parts.append(f'<td><strong>{_esc(a.get("title",""))}</strong><br>'
                     f'<span class="pm-action-desc">{_esc(a.get("description",""))}</span></td>')
        parts.append(f'<td>{_esc(a.get("owner_role",""))}</td>')
        parts.append(f'<td>{a.get("due_days","?")}</td>')
        parts.append(f'<td>{_esc(fw)}</td>')
        parts.append('</tr>')
    parts.append('</tbody></table>')
    return "".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
#  Footer / actions
# ─────────────────────────────────────────────────────────────────────────────


def _render_actions_footer(document: dict) -> str:
    pm_id = document.get("postmortem_id", "?")
    return f'''
<div class="pm-actions-footer">
  <button class="pm-regenerate-btn" data-pm-id="{_esc(pm_id)}">Regenerate</button>
  <button class="pm-push-jira-btn" data-pm-id="{_esc(pm_id)}">Push to Jira</button>
  <button class="pm-push-confluence-btn" data-pm-id="{_esc(pm_id)}">Push to Confluence</button>
  <button class="pm-export-pdf-btn" data-pm-id="{_esc(pm_id)}">Export PDF</button>
  <button class="pm-export-onepager-btn" data-pm-id="{_esc(pm_id)}">Compliance one-pager</button>
</div>'''


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _esc(s: Any) -> str:
    if s is None:
        return ""
    return html.escape(str(s), quote=True)


def _pretty(obj: Any) -> str:
    try:
        return json.dumps(obj, indent=2, default=str)
    except Exception:
        return str(obj)


__all__ = ["render_postmortem_html"]
