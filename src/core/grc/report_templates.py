"""ISO-native report templates over the audit pack.

The audit pack has all the data; a GRC/auditor buyer needs it in the FORMAT they
already produce. This renders three standard reports plus the root-cause and
lessons-learned content those standards require (which the platform did not produce
before):

  * ISO/IEC 27035  - security incident record (identification -> lessons-learned).
  * ISO/IEC 27001  - corrective-action (CAPA) + Annex-A control-gap register (Clause 10).
  * ISO 19011      - management-system audit report (scope/criteria/findings with
                     objective evidence/conclusions).

Root-cause and lessons-learned are DERIVED deterministically from the finding's
kill-chain entry point + the control that failed to prevent it, and from the driven
process improvements - so they are grounded, not LLM-invented.
"""
from __future__ import annotations

import html as _html
from typing import Any, Optional

from src.core.grc import phase_registry as _reg
from src.core.grc.control_gaps import _CONTROL_NAMES

# Incident category per entry-point phase (ISO 27035 classification).
_CATEGORY = {
    "oauth_device_code": "Unauthorised access - illicit OAuth consent",
    "iam:oauth_consent_excessive_scope": "Unauthorised access - illicit OAuth consent",
    "mfa_fatigue": "Unauthorised access - MFA compromise",
    "aitm_session": "Unauthorised access - session/token theft",
    "session_theft": "Unauthorised access - session/token theft",
    "sim_swap": "Unauthorised access - account takeover",
    "helpdesk_anomalous_reset": "Unauthorised access - social engineering",
    "ike_vpn_exploit": "Unauthorised access - perimeter exploitation",
    "firewall_threat": "Attempted intrusion - perimeter",
    "phishing_lure": "Unauthorised access - phishing",
}
_DEFAULT_CATEGORY = "Information security incident - confirmed intrusion"


def _entry_phase(finding: dict) -> Optional[str]:
    """The kill-chain entry point: the phase with the lowest kill-chain rank."""
    ranked = [(p, _reg.kc(p)) for p in (finding.get("phases") or [])]
    ranked = [(p, kc) for p, kc in ranked if kc]
    if not ranked:
        return (finding.get("phases") or [None])[0]
    return min(ranked, key=lambda x: x[1][0])[0]


def _control_name(fw: str, ctrl: str) -> str:
    return _CONTROL_NAMES.get(fw, {}).get(ctrl, ctrl)


def root_cause(finding: dict) -> dict:
    """Deterministic root cause: the entry-point technique succeeded because a specific
    control was not effective; the intrusion then progressed through the kill chain."""
    entry = _entry_phase(finding)
    kc = (finding.get("summary") or {}).get("occurred", {}).get("kill_chain") or []
    entry_label = kc[0] if kc else "the initial access"
    controls = _reg.controls(entry) if entry else {}
    iso = (controls.get("iso27001") or [])
    failed_ctrl = iso[0] if iso else "A.5.15"
    failed_name = _control_name("iso27001", failed_ctrl)
    progression = " -> ".join(kc) if kc else "the observed activity"
    statement = (
        f"Candidate root cause for review: examine {failed_ctrl} ({failed_name}) "
        f"in relation to {entry_label}. Observed phase sequence: {progression}. "
        "Control design, operating effectiveness and causation have not been established."
    )
    return {
        "entry_point_phase": entry,
        "failed_control": None,
        "candidate_control": {"framework": "iso27001", "control": failed_ctrl, "name": failed_name},
        "assertion_status": "candidate", "progression": kc, "statement": statement,
    }


def lessons_learned(finding: dict) -> list[str]:
    """Preventive lessons - the process/architecture improvements the finding drives."""
    drv = finding.get("drivers") or {}
    seen: list[str] = []
    for item in (drv.get("improvements") or []) + (drv.get("infrastructure") or []):
        if item not in seen:
            seen.append(item)
    return seen[:8]


def _actions(finding: dict) -> list[dict]:
    return [{"priority": n.get("priority"), "sla_hours": n.get("sla_hours"),
             "action": n.get("remediation"), "owner": n.get("owner")}
            for n in (finding.get("nonconformities") or [])]


def iso27035_incident_record(pack: dict, assessment_id: str) -> dict[str, Any]:
    """ISO/IEC 27035 security-incident record for each breach finding."""
    incidents = []
    for f in sorted(pack.get("findings", []), key=lambda _f: -float((_f.get("dread") or {}).get("overall_score") or 0)):
        occ = (f.get("summary") or {}).get("occurred", {})
        dread = f.get("dread") or {}
        entry = _entry_phase(f)
        prov = f.get("provenance") or {}
        vt = prov.get("valid_time") or {}
        crit = str(dread.get("overall_level")) == "critical"
        incidents.append({
            "incident_id": f.get("breach_ref"),
            "identification": {
                "responsible_actor": f.get("actor"),
                "verdict": f.get("verdict"),
                "entry_point": entry,
                "detected_by": "JanuSec deterministic detection + correlation",
            },
            "classification": {
                "category": _CATEGORY.get(entry, _DEFAULT_CATEGORY),
                "severity": dread.get("overall_level"),
                "dread_score": dread.get("overall_score"),
                "attack_complexity": (dread.get("attack_complexity") or {}).get("level"),
            },
            "timeline": {
                "first_observed": vt.get("from"),
                "last_observed": vt.get("to"),
                "duration": occ.get("duration"),
                "assessed_at": prov.get("transaction_time"),
            },
            "affected": {
                "identities": occ.get("affected_identities"),
                "hosts": occ.get("affected_hosts"),
                "asset_classes": occ.get("asset_classes"),
                "data_scope": occ.get("data_scope"),
                "blast_radius": (dread.get("components") or {}).get("affected", {}).get("blast_radius"),
            },
            "root_cause": root_cause(f),
            "response_actions": _actions(f),
            "lessons_learned": lessons_learned(f),
            "evidence": {"custody_content_hash": prov.get("evidence_content_hash"),
                         "cited_rows": f.get("evidence_rows")},
            "notification": {"breach_notification_required": None,
                             "deadline_hours": None,
                             "basis": "Requires approved applicability and classification evidence",
                             "status": "insufficient_information"},
        })
    return {"standard": "ISO/IEC 27035", "assessment_id": assessment_id,
            "incident_count": len(incidents), "incidents": incidents,
            "custody": pack.get("custody")}


def iso27001_capa_register(pack: dict, assessment_id: str) -> dict[str, Any]:
    """ISO/IEC 27001:2022 corrective-action register (Clause 10) + Annex-A gap summary."""
    capa = []
    for f in sorted(pack.get("findings", []), key=lambda _f: -float((_f.get("dread") or {}).get("overall_score") or 0)):
        rc = root_cause(f)
        for nc in (f.get("nonconformities") or []):
            capa.append({
                "nc_id": nc.get("nc_id"),
                "clause": "10.2 Nonconformity and corrective action",
                "control_refs": nc.get("control_refs"),
                "nonconformity": None,
                "candidate_concern": f"Review control relevance to {nc.get('phase')} ({f.get('actor')}).",
                "assertion_status": "candidate",
                "correction": nc.get("remediation"),
                "corrective_action": "; ".join(lessons_learned(f)[:3]) or "Review and strengthen the affected control.",
                "root_cause": rc["statement"],
                "owner": nc.get("owner"),
                "deadline_hours": nc.get("sla_hours"),
                "priority": nc.get("priority"),
                "objective_evidence_rows": nc.get("evidence_rows"),
                "status": nc.get("status", "open"),
            })
    return {"standard": "ISO/IEC 27001:2022", "assessment_id": assessment_id,
            "annex_a_gap_summary": (pack.get("control_gaps") or {}).get("summary"),
            "corrective_actions": capa, "custody": pack.get("custody")}


def iso19011_audit_report(pack: dict, assessment_id: str) -> dict[str, Any]:
    """ISO 19011:2018 management-system audit report - findings backed by objective
    evidence (the custody-hashed rows)."""
    frameworks = (pack.get("summary") or {}).get("frameworks") or []
    findings = []
    for f in sorted(pack.get("findings", []), key=lambda _f: -float((_f.get("dread") or {}).get("overall_score") or 0)):
        prov = f.get("provenance") or {}
        controls = sorted({c for nc in (f.get("nonconformities") or [])
                           for c in (nc.get("control_refs", {}).get("iso27001") or [])})
        findings.append({
            "classification": "Candidate control concern",
            "description": (f.get("summary") or {}).get("paragraphs", ["" ])[0],
            "controls_affected": controls,
            "severity": (f.get("dread") or {}).get("overall_level"),
            "objective_evidence": {
                "cited_rows": f.get("evidence_rows"),
                "content_hash": prov.get("evidence_content_hash"),
                "decision_id": prov.get("decision_id"),
            },
            "root_cause": root_cause(f)["statement"],
        })
    p1 = (pack.get("summary") or {}).get("p1_count", 0)
    conclusion = (
        f"{len(findings)} candidate control concern(s) require review. "
        "Proposed corrective actions support investigation; formal nonconformity "
        "and an audit opinion require an authorized control-effectiveness review."
    )
    return {
        "standard": "ISO 19011:2018",
        "assessment_id": assessment_id,
        "audit_scope": "Reconstruction and control-effectiveness assessment of the "
                       "supplied security telemetry.",
        "audit_criteria": frameworks or ["ISO/IEC 27001:2022 Annex A"],
        "methodology": "Evidence-based reconstruction from telemetry: deterministic "
                       "detection and correlation, grounded (non-hallucinating) analysis, "
                       "with every claim traceable to immutable, hash-verified evidence.",
        "findings": findings,
        "conclusions": conclusion,
        "auditor": "JanuSec - deterministic engine + governed AI (see /ai-governance)",
        "custody": pack.get("custody"),
    }


def incident_timeline(pack: dict, assessment_id: str) -> dict[str, Any]:
    """Per-incident kill-chain timeline for the interactive Investigation surface.

    A flat, view-ready contract derived from the same findings the reports use — no
    live ingest required. Each incident carries its ordered kill-chain narrative, the
    phase ids and MITRE techniques behind it, the affected assets, and the cited
    evidence rows (which the /rows/{i} endpoint resolves to raw events + custody hash).
    """
    incidents = []
    for f in sorted(pack.get("findings", []), key=lambda _f: -float((_f.get("dread") or {}).get("overall_score") or 0)):
        occ = (f.get("summary") or {}).get("occurred", {})
        dread = f.get("dread") or {}
        # Pair each kill-chain narrative step with its phase id where available; the
        # kill_chain is deduped by rank so it can be shorter than phases — zip is safe.
        labels = occ.get("kill_chain") or []
        phases = f.get("phases") or []
        steps = [{"label": lbl, "phase": phases[i] if i < len(phases) else None}
                 for i, lbl in enumerate(labels)]
        incidents.append({
            "incident_id": f.get("breach_ref"),
            "actor": f.get("actor"),
            "verdict": f.get("verdict"),
            "severity": dread.get("overall_level"),
            "dread_score": dread.get("overall_score"),
            "attack_complexity": (dread.get("attack_complexity") or {}).get("level"),
            "first_observed": occ.get("start"),
            "last_observed": occ.get("end"),
            "duration": occ.get("duration"),
            "kill_chain": steps,
            "phases": phases,
            "mitre": f.get("mitre") or [],
            "affected_hosts": occ.get("affected_hosts") or [],
            "affected_identities": occ.get("affected_identities") or [],
            "asset_classes": occ.get("asset_classes") or [],
            "data_scope": occ.get("data_scope"),
            "evidence_rows": f.get("evidence_rows") or [],
        })
    return {"standard": "JanuSec incident timeline", "assessment_id": assessment_id,
            "incident_count": len(incidents), "incidents": incidents}


# ── Print-friendly combined audit report (browser -> PDF) ────────────────────────

def _e(x) -> str:
    return _html.escape(str(x if x is not None else ""))


def _ul(items) -> str:
    items = [i for i in (items or []) if i]
    return "<ul>" + "".join(f"<li>{_e(i)}</li>" for i in items) + "</ul>" if items else "<p class='muted'>None.</p>"


def render_audit_report_html(pack: dict, assessment_id: str) -> str:
    """One print-friendly document combining the ISO 19011 audit report, the ISO 27035
    incident records, and the ISO 27001 corrective-action register — the deliverable an
    auditor prints to PDF and hands over."""
    ar = iso19011_audit_report(pack, assessment_id)
    ir = iso27035_incident_record(pack, assessment_id)
    ca = iso27001_capa_register(pack, assessment_id)
    custody = (pack.get("custody") or {}).get("digest", "")

    # ISO 19011 header + findings
    crit_rows = "".join(
        f"<tr><td>{_e(f['classification'])}</td><td>{_e(f['severity'])}</td>"
        f"<td>{_e(', '.join(f['controls_affected']))}</td>"
        f"<td class='mono'>{_e((f['objective_evidence'].get('content_hash') or '')[:16])}…</td></tr>"
        for f in ar["findings"]
    ) or "<tr><td colspan='4'>No nonconformities.</td></tr>"

    # ISO 27035 incidents
    inc_blocks = []
    for i in ir["incidents"]:
        cls = i["classification"]; tl = i["timeline"]; aff = i["affected"]; rc = i["root_cause"]
        acts = "".join(f"<li>[{_e(a['priority'])}/{_e(a['sla_hours'])}h] {_e(a['action'])} <em>({_e(a['owner'])})</em></li>"
                       for a in i["response_actions"][:6])
        notif = i["notification"]
        inc_blocks.append(f"""
        <section class="incident">
          <h3>{_e(i['incident_id'])} — {_e(i['identification']['responsible_actor'])}
            <span class="sev sev-{_e(cls['severity'])}">{_e(cls['severity']).upper()}</span></h3>
          <p><strong>Category:</strong> {_e(cls['category'])} ·
             <strong>DREAD:</strong> {_e(cls['dread_score'])} ·
             <strong>Attack complexity:</strong> {_e(cls['attack_complexity'])}</p>
          <p><strong>Timeline:</strong> {_e(tl['first_observed'])} → {_e(tl['last_observed'])} ({_e(tl['duration'])});
             assessed {_e(tl['assessed_at'])}</p>
          <p><strong>Affected:</strong> {_e(', '.join(aff['identities'] or []))} ·
             {_e(len(aff['hosts'] or []))} host(s) · {_e(', '.join(aff['asset_classes'] or []))} ·
             {_e(aff['data_scope'])} · blast radius: {_e(aff['blast_radius'])}</p>
          <p class="rc"><strong>Root cause:</strong> {_e(rc['statement'])}</p>
          <p><strong>Response actions:</strong></p><ul>{acts}</ul>
          <p><strong>Lessons learned:</strong></p>{_ul(i['lessons_learned'])}
          {'<p class="notif"><strong>Breach notification required</strong> — ' + _e(notif['basis']) + ' (' + _e(notif['deadline_hours']) + 'h)</p>' if notif['breach_notification_required'] else ''}
        </section>""")

    # ISO 27001 CAPA table
    capa_rows = "".join(
        f"<tr><td>{_e(c['nc_id'])}</td><td>{_e(c['priority'])}</td>"
        f"<td>{_e(', '.join((c.get('control_refs') or {}).get('iso27001', [])))}</td>"
        f"<td>{_e(c['correction'])}</td><td>{_e(c['corrective_action'])}</td>"
        f"<td>{_e(c['owner'])}/{_e(c['deadline_hours'])}h</td></tr>"
        for c in ca["corrective_actions"]
    ) or "<tr><td colspan='6'>No corrective actions.</td></tr>"
    gap = (ca.get("annex_a_gap_summary") or {}).get("iso27001") or {}

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Audit Report — {_e(assessment_id)}</title>
<style>
 body{{font:13px/1.55 Georgia,'Times New Roman',serif;color:#111;background:#fff;max-width:900px;margin:0 auto;padding:32px}}
 h1{{font-size:22px;margin:0 0 2px}} h2{{font-size:17px;border-bottom:2px solid #333;padding-bottom:4px;margin-top:28px}}
 h3{{font-size:14px;margin:14px 0 6px}} .muted{{color:#666}} .mono{{font-family:Consolas,monospace;font-size:11px}}
 table{{width:100%;border-collapse:collapse;margin:8px 0;font-size:12px}}
 th,td{{border:1px solid #bbb;padding:4px 7px;text-align:left;vertical-align:top}} th{{background:#f0f0f0}}
 .sev{{font-size:10px;padding:1px 6px;border-radius:3px;color:#fff}}
 .sev-critical{{background:#b30000}} .sev-high{{background:#d2691e}} .sev-medium{{background:#b8860b}} .sev-low{{background:#4682b4}}
 .incident{{border:1px solid #ccc;border-radius:6px;padding:12px 16px;margin:12px 0;page-break-inside:avoid}}
 .rc{{background:#fff8e1;padding:6px 10px;border-left:3px solid #b8860b}}
 .notif{{background:#fdecea;padding:6px 10px;border-left:3px solid #b30000}}
 .meta{{color:#555;font-size:12px}} ul{{margin:4px 0}} section{{page-break-inside:avoid}}
 @media print{{ body{{padding:0}} }}
</style></head><body>
<h1>Information Security Audit &amp; Incident Report</h1>
<p class="meta">Assessment {_e(assessment_id)} · Standards: ISO 19011:2018 · ISO/IEC 27035 · ISO/IEC 27001:2022 ·
   Auditor: {_e(ar['auditor'])} · Custody digest: <span class="mono">{_e(custody[:32])}…</span></p>

<h2>1. Audit report (ISO 19011:2018)</h2>
<p><strong>Scope:</strong> {_e(ar['audit_scope'])}</p>
<p><strong>Criteria:</strong> {_e(', '.join(ar['audit_criteria']))}</p>
<p><strong>Methodology:</strong> {_e(ar['methodology'])}</p>
<p><strong>Conclusions:</strong> {_e(ar['conclusions'])}</p>
<table><thead><tr><th>Finding</th><th>Severity</th><th>Controls affected</th><th>Objective evidence (hash)</th></tr></thead>
<tbody>{crit_rows}</tbody></table>

<h2>2. Incident records (ISO/IEC 27035)</h2>
{''.join(inc_blocks) if inc_blocks else '<p class="muted">No incidents.</p>'}

<h2>3. Corrective-action register (ISO/IEC 27001:2022, Clause 10.2)</h2>
<p class="meta">Annex A gap: {_e(gap.get('controls_failing'))} of {_e(gap.get('total_controls'))} controls with nonconformities (worst: {_e(gap.get('worst_severity'))}).</p>
<table><thead><tr><th>NC</th><th>Pri</th><th>ISO 27001</th><th>Correction</th><th>Corrective action (prevent recurrence)</th><th>Owner/SLA</th></tr></thead>
<tbody>{capa_rows}</tbody></table>
</body></html>"""
