"""GRC / Control-Assurance surface — serves the audit pack for an assessment.

Deliberately standalone (does not thread through the report-aggregation / persona-HTML
god-modules): reads assessment['audit_pack'] from REPORT_STORE and renders it three
ways — JSON (integration), a self-contained Control-Assurance HTML page (the demo
surface), and a CSV Nonconformity register (auditor-friendly).
"""
from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Response

from src.api.grc_auth import require_report_access

logger = logging.getLogger(__name__)

# Every GRC / evidence endpoint requires report access (bypassed in lite/dev/test/demo).
router = APIRouter(prefix="/api/v1", tags=["GRC / Control Assurance"],
                   dependencies=[Depends(require_report_access)])


def _load_audit_pack(assessment_id: str) -> dict:
    # Use the disk-aware loader the rest of the app uses, not a bare REPORT_STORE
    # lookup: after a _BoundedDict eviction or a server restart the in-memory entry
    # is gone but the assessment is still recoverable from disk. A demo-seeded pack
    # written straight to data/assessments/ is discovered the same way.
    try:
        from src.api.deep_analyze.persistence import _get_assessment_cached
    except Exception:  # pragma: no cover
        from api.deep_analyze.persistence import _get_assessment_cached  # type: ignore
    assessment = _get_assessment_cached(assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail=f"assessment {assessment_id!r} not found")
    pack = assessment.get("audit_pack")
    if not pack:
        # A valid assessment with no breach findings still returns an empty pack.
        return {"findings": [], "nonconformities": [], "control_coverage": {},
                "recommended_investments": [], "recommended_infrastructure": [],
                "summary": {"total_findings": 0, "total_ncs": 0, "by_priority": {},
                            "frameworks": [], "p1_count": 0}}
    return pack


@router.get("/assessments/{assessment_id}/audit-pack", summary="GRC audit pack (JSON)")
def get_audit_pack(assessment_id: str):
    return _load_audit_pack(assessment_id)


@router.get("/assessments/{assessment_id}/summary", summary="3-paragraph executive summary (JSON)")
def get_executive_summary(assessment_id: str):
    pack = _load_audit_pack(assessment_id)
    es = pack.get("executive_summary")
    if not es:
        raise HTTPException(status_code=404, detail="no breach finding to summarise")
    return es


def _custody_hash(obj) -> str:
    """Tamper-evident SHA-256 over the canonical JSON of an evidence object."""
    try:
        blob = json.dumps(obj, sort_keys=True, default=str, separators=(",", ":"))
    except Exception:
        blob = str(obj)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@router.get("/assessments/{assessment_id}/rows/{row_index}", summary="Raw event for a cited row (claim -> evidence)")
def get_evidence_row(assessment_id: str, row_index: int):
    """Resolve a cited row index to its raw normalized event, with a custody hash so
    the evidence behind any narrative claim / Nonconformity is independently verifiable."""
    event = None
    # Authoritative source: the DuckDB row store.
    try:
        from src.core.ingest import store as _store
        rows = _store.load_rows(assessment_id, row_indices=[int(row_index)], min_triage=0.0, limit=1)
        if rows:
            event = rows[0]
    except Exception:
        event = None
    # Fallback: the persisted assessment's evidence/rows list. Disk-aware (same reason
    # as _load_audit_pack) so a seeded/evicted assessment still resolves its evidence.
    if event is None:
        try:
            from src.api.deep_analyze.persistence import _get_assessment_cached
        except Exception:  # pragma: no cover
            from api.deep_analyze.persistence import _get_assessment_cached  # type: ignore
        a = _get_assessment_cached(assessment_id) or {}
        for key in ("evidence_rows", "rows", "all_rows", "flagged_events"):
            for r in (a.get(key) or []):
                if isinstance(r, dict) and int(r.get("row_index", -1)) == int(row_index):
                    event = r
                    break
            if event is not None:
                break
    if event is None:
        raise HTTPException(status_code=404, detail=f"row {row_index} not found for assessment {assessment_id!r}")
    return {
        "assessment_id": assessment_id,
        "row_index": int(row_index),
        "event": event,
        "custody": {
            "sha256": _custody_hash(event),
            "source_file": event.get("_source") or event.get("source_file"),
            "source_type": event.get("_source_type") or event.get("source_type"),
        },
    }


@router.get("/assessments/{assessment_id}/mitre-navigator", summary="ATT&CK Navigator layer (JSON)")
def get_mitre_navigator(assessment_id: str):
    pack = _load_audit_pack(assessment_id)
    from src.core.grc.mitre_navigator import build_navigator_layer
    layer = build_navigator_layer(pack, name=f"JanuSec {assessment_id}")
    return Response(content=json.dumps(layer, indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="navigator-{assessment_id}.json"'})


@router.get("/assessments/{assessment_id}/report/iso27035", summary="ISO/IEC 27035 incident record (JSON)")
def get_iso27035(assessment_id: str):
    from src.core.grc.report_templates import iso27035_incident_record
    return iso27035_incident_record(_load_audit_pack(assessment_id), assessment_id)


@router.get("/assessments/{assessment_id}/report/iso27001", summary="ISO/IEC 27001 corrective-action register (JSON)")
def get_iso27001(assessment_id: str):
    from src.core.grc.report_templates import iso27001_capa_register
    return iso27001_capa_register(_load_audit_pack(assessment_id), assessment_id)


@router.get("/assessments/{assessment_id}/report/iso19011", summary="ISO 19011 audit report (JSON)")
def get_iso19011(assessment_id: str):
    from src.core.grc.report_templates import iso19011_audit_report
    return iso19011_audit_report(_load_audit_pack(assessment_id), assessment_id)


@router.get("/assessments/{assessment_id}/timeline",
            summary="Per-incident kill-chain timeline (JSON, for the Investigation surface)")
def get_incident_timeline(assessment_id: str):
    from src.core.grc.report_templates import incident_timeline
    return incident_timeline(_load_audit_pack(assessment_id), assessment_id)


@router.get("/assessments/{assessment_id}/report.html",
            summary="Combined ISO 19011 + 27035 + 27001 audit report (print-friendly HTML)")
def get_audit_report_html(assessment_id: str):
    from src.core.grc.report_templates import render_audit_report_html
    pack = _load_audit_pack(assessment_id)
    return Response(content=render_audit_report_html(pack, assessment_id), media_type="text/html")


@router.get("/ai-governance", summary="Platform AI-governance self-assessment (ISO 42001 / EU AI Act / MAESTRO)")
def get_ai_governance():
    from src.core.grc.ai_governance import ai_governance_posture
    return ai_governance_posture()


@router.get("/assessments/{assessment_id}/ai-surface", summary="AI/agent attack surface (MAESTRO)")
def get_ai_surface(assessment_id: str):
    from src.core.grc.ai_governance import ai_surface_maestro
    return ai_surface_maestro(_load_audit_pack(assessment_id))


@router.get("/assessments/{assessment_id}/audit-pack.csv", summary="Nonconformity register (CSV)")
def get_audit_pack_csv(assessment_id: str):
    pack = _load_audit_pack(assessment_id)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["nc_id", "priority", "sla_hours", "dread_score", "dread_level", "actor",
                "phase", "owner", "remediation", "iso27001", "soc2", "mitre", "evidence_rows", "status"])
    for nc in pack.get("nonconformities", []):
        cr = nc.get("control_refs") or {}
        w.writerow([
            nc.get("nc_id"), nc.get("priority"), nc.get("sla_hours"),
            nc.get("dread_score"), nc.get("dread_level"), nc.get("actor"), nc.get("phase"),
            nc.get("owner"), nc.get("remediation"),
            " ".join(cr.get("iso27001", [])), " ".join(cr.get("soc2", [])),
            " ".join(nc.get("mitre", [])), " ".join(str(r) for r in nc.get("evidence_rows", [])),
            nc.get("status"),
        ])
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="audit-pack-{assessment_id}.csv"'})


@router.get("/assessments/{assessment_id}/audit-pack.html", summary="Control-Assurance page (HTML)")
def get_audit_pack_html(assessment_id: str):
    pack = _load_audit_pack(assessment_id)
    return Response(content=render_control_assurance_html(pack, assessment_id), media_type="text/html")


# ── HTML render ──────────────────────────────────────────────────────────────────

def _e(x) -> str:
    return html.escape(str(x if x is not None else ""))


def _dread_bar(score: float, level: str) -> str:
    pct = max(0, min(100, int((float(score) / 10.0) * 100)))
    colour = {"critical": "#ef4444", "high": "#f59e0b", "medium": "#eab308",
              "low": "#3b82f6", "trace": "#64748b"}.get(str(level), "#64748b")
    return (f'<div style="background:#1e293b;border-radius:4px;height:14px;width:100%;overflow:hidden">'
            f'<div style="background:{colour};height:100%;width:{pct}%"></div></div>')


def _finding_html(f: dict) -> str:
    d = f.get("dread") or {}
    comps = d.get("components") or {}
    drv = f.get("drivers") or {}
    rows = [
        f'<div class="finding">',
        f'<div class="fh"><span class="actor">{_e(f.get("actor"))}</span>'
        f'<span class="verdict">{_e(f.get("verdict"))}</span>'
        f'<span class="dread">DREAD {_e(d.get("overall_score"))} · {_e(d.get("overall_level")).upper()}</span></div>',
        '<table class="dread"><tbody>',
    ]
    labels = [("damage", "Damage"), ("reproducibility", "Reproducibility"),
              ("exploitability", "Exploitability"), ("affected", "Affected"),
              ("discoverability", "Discoverability")]
    for key, label in labels:
        c = comps.get(key) or {}
        rows.append(
            f'<tr><td class="lbl">{label}</td>'
            f'<td class="scr">{_e(c.get("score"))}</td>'
            f'<td class="bar">{_dread_bar(c.get("score") or 0, c.get("level") or "")}</td>'
            f'<td class="why">{_e(c.get("rationale"))}</td></tr>'
        )
    rows.append('</tbody></table>')
    # drivers
    def _drv(title, items, colour):
        if not items:
            return ""
        lis = "".join(f"<li>{_e(i)}</li>" for i in items)
        return f'<div class="drv"><strong style="color:{colour}">{title}</strong><ul>{lis}</ul></div>'
    rows.append('<div class="drivers">')
    rows.append(_drv("Infrastructure changes", drv.get("infrastructure"), "#60a5fa"))
    rows.append(_drv("Security investments (buy)", drv.get("investments"), "#34d399"))
    rows.append(_drv("Process improvements", drv.get("improvements"), "#a78bfa"))
    rows.append('</div>')
    # NCs for this finding
    rows.append('<table class="nc"><thead><tr><th>NC</th><th>Pri</th><th>SLA</th>'
                '<th>Remediation</th><th>ISO 27001</th><th>SOC 2</th><th>Owner</th></tr></thead><tbody>')
    for nc in f.get("nonconformities", []):
        cr = nc.get("control_refs") or {}
        rows.append(
            f'<tr><td>{_e(nc.get("nc_id"))}</td>'
            f'<td class="pri pri-{_e(nc.get("priority"))}">{_e(nc.get("priority"))}</td>'
            f'<td>{_e(nc.get("sla_hours"))}h</td>'
            f'<td>{_e(nc.get("remediation"))}</td>'
            f'<td>{_e(", ".join(cr.get("iso27001", [])))}</td>'
            f'<td>{_e(", ".join(cr.get("soc2", [])))}</td>'
            f'<td>{_e(nc.get("owner"))}</td></tr>'
        )
    rows.append('</tbody></table></div>')
    return "".join(rows)


def _framework_gap_html(pack: dict) -> str:
    cg = (pack.get("control_gaps") or {})
    summary = cg.get("summary") or {}
    gaps = cg.get("gaps") or {}
    if not summary:
        return ""
    sev_col = {"critical": "#ef4444", "high": "#f59e0b", "medium": "#eab308",
               "low": "#3b82f6", "trace": "#64748b"}
    blocks = []
    for fw in sorted(summary.keys()):
        info = summary[fw]
        failing = info.get("controls_failing", 0)
        total = info.get("total_controls")
        pct = info.get("gap_pct")
        worst = info.get("worst_severity", "low")
        bar = ""
        if pct is not None:
            bar = (f'<div style="background:#1e293b;border-radius:4px;height:10px;width:160px;'
                   f'display:inline-block;overflow:hidden;vertical-align:middle">'
                   f'<div style="background:{sev_col.get(worst)};height:100%;width:{min(100,pct)}%"></div></div>')
        denom = f" of {total}" if total else ""
        ctrl_rows = "".join(
            f'<tr><td class="c">{_e(r.get("control"))}</td><td>{_e(r.get("name"))}</td>'
            f'<td style="color:{sev_col.get(r.get("severity"),"#94a3b8")}">{_e(r.get("severity")).upper()}</td>'
            f'<td>{_e(r.get("finding_count"))}</td></tr>'
            for r in sorted(gaps.get(fw, {}).values(), key=lambda x: -x.get("worst_dread", 0))
        )
        blocks.append(
            f'<div class="fwgap"><div class="fwh"><strong>{_e(fw.upper())}</strong> '
            f'<span style="color:{sev_col.get(worst)}">{failing}{denom} controls with nonconformities</span> {bar}</div>'
            f'<table class="nc"><thead><tr><th>Control</th><th>Name</th><th>Severity</th><th>Findings</th></tr></thead>'
            f'<tbody>{ctrl_rows}</tbody></table></div>'
        )
    return ('<div class="budget" style="margin-bottom:18px"><h2>Framework Gap — controls with nonconformities</h2>'
            '<div class="sub">A control linked to a confirmed breach is a nonconformity; severity is the worst linked finding.</div>'
            + "".join(blocks) + '</div>')


def render_control_assurance_html(pack: dict, assessment_id: str) -> str:
    s = pack.get("summary") or {}
    findings = pack.get("findings") or []
    invest = pack.get("recommended_investments") or []
    frameworks = ", ".join(s.get("frameworks") or []) or "—"
    framework_gap_html = _framework_gap_html(pack)
    invest_rows = "".join(
        f'<tr><td class="cnt">{_e(i.get("findings"))}×</td><td>{_e(i.get("item"))}</td></tr>'
        for i in invest
    ) or '<tr><td colspan="2">No investments derived.</td></tr>'
    findings_html = "".join(_finding_html(f) for f in findings) or "<p>No breach findings in this assessment.</p>"
    # Executive summary block — front and centre.
    es = pack.get("executive_summary") or {}
    es_html = ""
    if es.get("paragraphs"):
        paras = "".join(f'<p class="es-p"><span class="es-n">¶{i}</span>{_e(p)}</p>'
                        for i, p in enumerate(es["paragraphs"], 1))
        es_html = (f'<div class="exec"><div class="es-head">{_e(es.get("headline"))}</div>{paras}</div>')
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Control Assurance — {_e(assessment_id)}</title>
<style>
 body{{background:#0f172a;color:#e2e8f0;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:24px}}
 h1{{font-size:20px;margin:0 0 4px}} .sub{{color:#94a3b8;margin-bottom:18px}}
 .kpis{{display:flex;gap:14px;margin-bottom:22px;flex-wrap:wrap}}
 .kpi{{background:#1e293b;border-radius:8px;padding:12px 18px;min-width:120px}}
 .kpi .n{{font-size:24px;font-weight:700}} .kpi .l{{color:#94a3b8;font-size:12px}}
 .finding{{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:16px;margin-bottom:18px}}
 .fh{{display:flex;gap:12px;align-items:center;margin-bottom:10px}}
 .actor{{font-weight:700;font-size:16px}} .verdict{{color:#f87171;font-size:12px;border:1px solid #7f1d1d;border-radius:4px;padding:1px 6px}}
 .dread{{margin-left:auto;color:#fbbf24;font-weight:600}}
 table{{width:100%;border-collapse:collapse;margin:8px 0;font-size:13px}}
 table.dread td{{padding:3px 8px;vertical-align:middle;border-bottom:1px solid #1f2937}}
 table.dread .lbl{{width:120px;color:#cbd5e1}} .scr{{width:34px;font-weight:700;text-align:right}} .bar{{width:120px}} .why{{color:#94a3b8}}
 .drivers{{display:flex;gap:16px;flex-wrap:wrap;margin:10px 0}}
 .drv{{flex:1;min-width:220px}} .drv ul{{margin:4px 0 0;padding-left:16px}} .drv li{{margin:2px 0;color:#cbd5e1}}
 table.nc th{{text-align:left;color:#94a3b8;border-bottom:1px solid #334155;padding:4px 8px;font-size:12px}}
 table.nc td{{padding:4px 8px;border-bottom:1px solid #1f2937;vertical-align:top}}
 .pri-P1{{color:#ef4444;font-weight:700}} .pri-P2{{color:#f59e0b}} .pri-P3{{color:#eab308}}
 .budget{{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:16px}}
 .budget h2{{font-size:15px;margin:0 0 8px}} .budget .cnt{{color:#34d399;font-weight:700;width:44px}}
 .exec{{background:#0b1220;border:2px solid #334155;border-radius:12px;padding:18px 22px;margin-bottom:22px}}
 .es-head{{font-weight:700;font-size:16px;color:#fbbf24;margin-bottom:12px}}
 .es-p{{margin:0 0 10px;font-size:14.5px;line-height:1.6}} .es-p:last-child{{margin-bottom:0}}
 .es-n{{display:inline-block;color:#60a5fa;font-weight:700;margin-right:8px}}
</style></head><body>
<h1>Control Assurance — Auditable Findings</h1>
<div class="sub">Assessment {_e(assessment_id)} · Frameworks: {_e(frameworks)}</div>
{es_html}
<div class="kpis">
 <div class="kpi"><div class="n">{_e(s.get('total_findings', 0))}</div><div class="l">Findings</div></div>
 <div class="kpi"><div class="n">{_e(s.get('total_ncs', 0))}</div><div class="l">Nonconformities</div></div>
 <div class="kpi"><div class="n" style="color:#ef4444">{_e(s.get('p1_count', 0))}</div><div class="l">P1 (contain now)</div></div>
</div>
{framework_gap_html}
{findings_html}
<div class="budget">
 <h2>Recommended Security Investments — CISO budget view</h2>
 <div class="sub">Ranked by how many findings each investment would mitigate.</div>
 <table><tbody>{invest_rows}</tbody></table>
</div>
</body></html>"""
