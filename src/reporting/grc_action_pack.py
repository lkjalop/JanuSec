"""Printable five-section GRC Action Pack rendered from CaseEvidenceViewModel v2."""

from __future__ import annotations

import html
from typing import Any


def _e(value: Any) -> str:
    return html.escape(str(value if value not in (None, "") else "Not established"))


def _items(values: list[Any], render) -> str:
    return "".join(render(value) for value in values) or '<p class="empty">No supported items available.</p>'


def _brief(value: Any) -> str:
    if value in (None, "", [], {}):
        return "Not established"
    if isinstance(value, list):
        return "; ".join(
            str(item.get("title") or item.get("summary") or item) if isinstance(item, dict) else str(item)
            for item in value
        )
    if isinstance(value, dict):
        return "; ".join(f"{key}: {item}" for key, item in value.items())
    return str(value)


def render_grc_action_pack(view: dict[str, Any]) -> str:
    case = view["case"]
    summary = view["breach_summary"]
    story = view.get("attack_story") or {}
    context = view.get("report_context") or {}
    posture = view.get("posture") or {}
    model = view.get("model_execution") or {}
    milestones = story.get("milestones") or []
    services = view.get("business_impact") or []
    action_plan = view.get("action_plan") or {}
    actions = [
        *[item for item in action_plan.get("actions") or [] if isinstance(item, dict)],
        *[item for item in view.get("corrective_actions") or [] if isinstance(item, dict)],
    ]
    decisions = action_plan.get("decisions_required") or view.get("immediate_decisions") or []
    controls = view.get("control_impacts") or []
    obligation_result = view.get("compliance_obligations") or {}
    obligations = obligation_result.get("obligations") or []
    gaps = view.get("coverage_gaps") or []
    hypotheses = view.get("hypotheses") or []
    domains = view.get("source_domains") or []
    confirmed = [item for item in milestones if item.get("status") == "observed"]
    suspected = [item for item in milestones if item.get("status") in {"inferred", "suspected", "attempted", "unknown"}]
    containment = view.get("containment") or []
    graph_status = str(context.get("graph_projection_status") or "unrecorded")
    graph_warning = (
        "" if graph_status == "current" else
        f'<p class="warning"><strong>Graph projection: {_e(graph_status)}</strong>. '
        'Causal reconstruction is provisional until a current immutable projection receipt is available.</p>'
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>JanusSec GRC Action Pack — {_e(case['id'])}</title>
<style>
@page{{size:A4;margin:14mm}}*{{box-sizing:border-box}}body{{font:12px/1.45 Arial,sans-serif;color:#172027;margin:0;background:#e9eef0}}
.page{{background:#fff;width:210mm;min-height:297mm;margin:10px auto;padding:14mm;page-break-after:always;box-shadow:0 2px 12px #0002}}.page:last-child{{page-break-after:auto}}
h1{{font-size:25px;margin:0 0 4px}}h2{{font-size:18px;border-bottom:2px solid #16776f;padding-bottom:5px}}h3{{font-size:13px;margin-bottom:4px}}p{{margin:5px 0 10px}}
.meta,.grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}}.grid.four{{grid-template-columns:repeat(4,1fr)}}.card{{border:1px solid #cad5d9;border-radius:6px;padding:9px}}.label{{font-size:9px;text-transform:uppercase;color:#5c7078;font-weight:bold}}.value{{font-weight:bold;margin-top:3px}}
table{{width:100%;border-collapse:collapse;margin:8px 0 14px}}th,td{{border:1px solid #ccd5d8;padding:6px;text-align:left;vertical-align:top}}th{{background:#edf4f4;font-size:10px}}.status{{color:#16776f;font-weight:bold}}.warning{{border-left:4px solid #c68318;background:#fff7e7;padding:8px}}.empty{{color:#687b82;font-style:italic}}.foot{{margin-top:18px;font-size:9px;color:#6b7d83}}
@media print{{body{{background:#fff}}.page{{margin:0;box-shadow:none}}}}@media(max-width:760px){{.page{{width:auto;min-height:0;margin:0;padding:18px}}.meta,.grid,.grid.four{{grid-template-columns:1fr}}table{{display:block;overflow:auto}}}}
</style></head><body>
<div class="page meta" style="min-height:0"><span>Tenant: {_e(case.get('tenant_id'))}</span><span>Case: {_e(case.get('id'))}</span><span>Assessment: {_e(case.get('assessment_id') or case.get('id'))}</span><span>As known at: {_e(context.get('as_known_at') or 'Current evidence')}</span><span>Historical receipt: {_e((context.get('historical_receipt') or {}).get('receipt_hash') or 'Unrecorded')}</span></div>
<section class="page"><div class="label">PAGE 1 · EXECUTIVE INCIDENT BRIEF</div><h1>{_e(summary.get('headline'))}</h1>{graph_warning}<p>{_e(summary.get('what_happened'))}</p>
<div class="grid four"><div class="card"><div class="label">Breach status</div><div class="value">{_e(posture.get('breach_status'))}</div></div><div class="card"><div class="label">Evidence confidence</div><div class="value">{_e(posture.get('evidence_confidence'))}</div></div><div class="card"><div class="label">Impact</div><div class="value">{_e(posture.get('impact'))}</div></div><div class="card"><div class="label">Review</div><div class="value">{_e(context.get('review_status'))}</div></div></div>
<h2>Entry, persistence and blast radius</h2><div class="grid"><div class="card"><div class="label">Entry vector</div>{_e(_brief(story.get('entry_vector')))}</div><div class="card"><div class="label">Persistence</div>{_e(_brief(story.get('persistence')))}</div><div class="card"><div class="label">Blast radius</div>{_e(_brief(story.get('blast_radius')))}</div><div class="card"><div class="label">Containment</div>{_e(_brief(containment))}</div></div>
<h2>Confirmed versus suspected impact</h2><div class="grid"><div class="card"><div class="label">Observed</div>{_e(_brief(confirmed))}</div><div class="card"><div class="label">Suspected / unresolved</div>{_e(_brief(suspected))}</div></div>
<h2>Business services affected</h2>{_items(services, lambda s: f'<div class="card"><strong>{_e(s.get("name"))}</strong> — {_e(s.get("status"))}<br>{_e(s.get("impact"))}</div>')}
<h2>Three immediate decisions</h2>{_items(decisions[:3], lambda d: f'<div class="card"><strong>{_e(d.get("priority"))}: {_e(d.get("question") or d.get("decision") or d.get("title"))}</strong><br>{_e(d.get("rationale") or d.get("status"))}<br><span class="label">Owner: {_e(d.get("owner_role"))} · Due {_e(d.get("due_within"))}</span></div>')}
<div class="foot">Evidence Pack {_e(context.get('evidence_pack_hash'))} · Graph receipt {_e(context.get('graph_receipt_hash'))} ({_e(graph_status)}) · Provider {_e(model.get('provider'))}/{_e(model.get('model'))} · External transfer {_e(model.get('external_data_transfer'))}</div></section>

<section class="page"><div class="label">PAGE 2 · TOP-LEVEL BREACH RECONSTRUCTION</div><h1>Attack story</h1>
<table><thead><tr><th>Time</th><th>Phase</th><th>Milestone</th><th>Status</th><th>Evidence</th></tr></thead><tbody>{_items(milestones, lambda m: f'<tr><td>{_e(m.get("occurred_at"))}</td><td>{_e(m.get("phase"))}</td><td><strong>{_e(m.get("title"))}</strong><br>{_e(m.get("summary"))}</td><td>{_e(m.get("status"))}</td><td>{len(m.get("evidence_ids") or [])}</td></tr>')}</tbody></table>
<h2>Source domains represented</h2><div class="grid">{_items(domains, lambda d: f'<div class="card"><strong>{_e(d.get("domain"))}</strong><br>{_e(d.get("row_count"))} rows · {_e(d.get("scope"))}</div>')}</div>
<h2>Alternative explanations</h2>{_items(hypotheses, lambda h: f'<div class="card"><strong>{_e(h.get("title") or h.get("hypothesis"))}</strong><br>{_e(h.get("summary") or h.get("basis"))}</div>')}</section>

<section class="page"><div class="label">PAGE 3 · TECHNICAL RECONSTRUCTION AND EVIDENCE GAPS</div><h1>Authorization and evidence detail</h1>
<table><thead><tr><th>Principal</th><th>Action</th><th>Resource</th><th>Outcome</th><th>Roles / policies</th></tr></thead><tbody>{_items((view.get('authorization_paths') or [])[:40], lambda a: f'<tr><td>{_e(a.get("principal"))}</td><td>{_e(a.get("action"))}</td><td>{_e(a.get("resource"))}</td><td>{_e(a.get("outcome"))}</td><td>{_e(", ".join((a.get("roles") or []) + (a.get("policies") or [])))}</td></tr>')}</tbody></table>
<h2>Coverage gaps</h2>{_items(gaps, lambda gap: f'<p class="warning">{_e(gap.get("gap") if isinstance(gap, dict) else gap)}</p>')}
<p class="foot">Absence of telemetry is not evidence of absence. Candidate relationships are not promoted to causal edges without backend-authored typed evidence.</p></section>

<section class="page"><div class="label">PAGE 4 · CONTROL-IMPACT ASSESSMENT</div><h1>Candidate control impacts</h1><p class="warning">Telemetry may identify a possible weakness. It does not establish formal nonconformity without control-design and operating-effectiveness review.</p>
<table><thead><tr><th>Framework</th><th>Control</th><th>Assertion</th><th>Basis</th><th>Evidence</th><th>Review</th></tr></thead><tbody>{_items(controls, lambda c: f'<tr><td>{_e(c.get("framework"))}</td><td><strong>{_e(c.get("control_id"))}</strong><br>{_e(c.get("title"))}</td><td>{_e(c.get("assertion_status"))}</td><td>{_e(c.get("basis"))}</td><td>{len(c.get("supporting_evidence_ids") or [])}</td><td>{_e(c.get("reviewer_status"))}</td></tr>')}</tbody></table>
<h2>Compliance-obligation decisions</h2><p>These are evidence-gated triage decisions, not legal conclusions. Missing or stale classification and applicability receipts require abstention.</p>
<table><thead><tr><th>Authority / jurisdiction</th><th>Obligation</th><th>Decision</th><th>Matched scope</th><th>Window / source</th><th>Next owner</th></tr></thead><tbody>{_items(obligations, lambda o: f'<tr><td>{_e(o.get("authority"))}<br>{_e(o.get("jurisdiction"))}</td><td><strong>{_e(o.get("obligation_id"))}</strong><br>v{_e(o.get("version"))}</td><td>{_e(o.get("decision_status"))}</td><td>Assets: {_e(", ".join(o.get("matched_asset_ids") or []))}<br>Services: {_e(", ".join(o.get("matched_service_ids") or []))}<br>Data: {_e(", ".join(o.get("matched_data_categories") or []))}</td><td>{_e(o.get("notification_window"))}<br>{_e(o.get("source_reference"))}</td><td>{_e(o.get("owner_role"))}<br>{"Review required" if o.get("review_required") else "No current review trigger"}</td></tr>')}</tbody></table></section>

<section class="page"><div class="label">PAGE 5 · ACTION AND VERIFICATION REGISTER</div><h1>What happens next, who owns it, and what proves closure</h1>
<p class="warning">Framework references provide traceability. Actions and formal control conclusions remain subject to authenticated human approval.</p>
<table><thead><tr><th>When / priority</th><th>Exact action and evidence basis</th><th>Owner / approver</th><th>Status / control consequence</th><th>Verification and required closure proof</th></tr></thead><tbody>{_items(actions, lambda a: f'<tr><td><strong>{_e(a.get("horizon"))}</strong><br>{_e(a.get("priority"))}<br><span class="label">Due {_e(a.get("due_within") or a.get("due_at") or a.get("due_date"))}</span></td><td><strong>{_e(a.get("exact_action") or a.get("action") or a.get("title"))}</strong><br><span class="label">Why</span> {_e(a.get("why") or a.get("root_cause"))}<br><span class="label">Evidence</span> {_e(", ".join(a.get("supporting_evidence_ids") or []))}</td><td>{_e(a.get("owner") or a.get("owner_role"))}<br><span class="label">Approver</span> {_e(a.get("accountable_approver_role") or a.get("analyst_signoff"))}</td><td>{_e(a.get("status") or a.get("approval_status"))}<br><span class="label">Conclusion</span> {_e(a.get("control_consequence") or a.get("correction"))}<br><span class="label">Compensating control</span> {_e(a.get("compensating_control"))}</td><td>{_e(a.get("verification_procedure") or a.get("verification") or a.get("success_criteria"))}<br><span class="label">Closure proof</span> {_e("; ".join(a.get("required_closure_evidence") or []))}</td></tr>')}</tbody></table>
<h2>Containment status</h2>{_items(containment, lambda item: f'<div class="card"><strong>{_e(item.get("object") or item.get("name") or item.get("action"))}</strong> — {_e(item.get("status"))}<br>{_e(item.get("verification"))}</div>')}
<div class="foot">Generated from CaseEvidenceViewModel v2 · Action Plan {_e(action_plan.get('content_hash'))} · {_e(context.get('generated_at'))} · Human approval remains authoritative.</div></section>
</body></html>"""


__all__ = ["render_grc_action_pack"]
