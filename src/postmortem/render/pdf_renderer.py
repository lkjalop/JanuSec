"""
PDF Renderer — Full postmortem export
======================================

Uses ReportLab matching the existing pattern in
``src/api/report_endpoints.py`` so the look-and-feel is consistent with
the persona reports already in production.

OUTPUT
------
A single PDF file with all 7 sections, table-of-contents, header/footer
on every page, and an evidence provenance appendix.

USAGE
-----
    from src.postmortem.render import render_postmortem_pdf

    out_path = render_postmortem_pdf(
        document=postmortem,
        out_path="/tmp/postmortem-pm-9b3c7e8a.pdf",
    )
    # returns out_path on success
"""
from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# Lazy import — same pattern as report_endpoints.py
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, KeepTogether,
    )
    _REPORTLAB_AVAILABLE = True
except ImportError:
    _REPORTLAB_AVAILABLE = False


def render_postmortem_pdf(*, document: dict, out_path: str) -> str:
    """Render the postmortem to a PDF file. Returns the output path."""
    if not _REPORTLAB_AVAILABLE:
        raise RuntimeError("reportlab not installed — required for PDF export")

    from src.postmortem.postmortem_assembler import get_computed_section

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    doc = SimpleDocTemplate(
        out_path,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        title=f"JanuSec Postmortem {document.get('postmortem_id','?')}",
    )

    styles = _build_styles()
    flowables: list = []

    flowables.extend(_pdf_header(document, styles))
    flowables.extend(_pdf_verdict_block(document, styles))
    flowables.extend(_pdf_data_quality(document, styles))
    flowables.append(PageBreak())

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
        flowables.extend(_pdf_render_section(sec_id, title, section, computed, styles))
        flowables.append(Spacer(1, 8 * mm))

    flowables.append(PageBreak())
    flowables.extend(_pdf_evidence_provenance(document, styles))

    doc.build(flowables, onFirstPage=_pdf_header_footer, onLaterPages=_pdf_header_footer)
    return out_path


def _build_styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "h1":      ParagraphStyle("h1", parent=base["Heading1"], fontSize=18, spaceAfter=8),
        "h2":      ParagraphStyle("h2", parent=base["Heading2"], fontSize=14, spaceAfter=6),
        "h3":      ParagraphStyle("h3", parent=base["Heading3"], fontSize=11, spaceAfter=4),
        "body":    ParagraphStyle("body", parent=base["BodyText"], fontSize=9, leading=12),
        "small":   ParagraphStyle("small", parent=base["BodyText"], fontSize=8, leading=10,
                                  textColor=colors.HexColor("#666")),
        "warning": ParagraphStyle("warning", parent=base["BodyText"], fontSize=9, leading=12,
                                  backColor=colors.HexColor("#fff8dc"), borderPadding=4),
        "stub":    ParagraphStyle("stub", parent=base["BodyText"], fontSize=9, leading=12,
                                  textColor=colors.HexColor("#888"), italic=True),
    }


def _pdf_header(document: dict, styles: dict) -> list:
    pm_id = document.get("postmortem_id", "?")
    cluster_id = document.get("cluster_id", "?")
    tx_time = document.get("transaction_time", "?")
    return [
        Paragraph("JanuSec Postmortem", styles["h1"]),
        Paragraph(f"<b>Postmortem ID:</b> {pm_id}", styles["body"]),
        Paragraph(f"<b>Cluster:</b> {cluster_id}", styles["body"]),
        Paragraph(f"<b>Assembled:</b> {tx_time}", styles["body"]),
        Paragraph(f"<b>Tenant:</b> {document.get('tenant_id','?')}", styles["body"]),
        Spacer(1, 4 * mm),
    ]


def _pdf_verdict_block(document: dict, styles: dict) -> list:
    v = document.get("verdict") or {}
    return [
        Paragraph("Verdict", styles["h2"]),
        Paragraph(f"<b>Platform verdict:</b> {v.get('platform_verdict','?')} "
                  f"(confidence {v.get('confidence',0.0):.2f})", styles["body"]),
        Paragraph(f"<b>Materiality:</b> {v.get('materiality_assessment','?')}", styles["body"]),
        Paragraph(f"<b>Rationale:</b> {v.get('materiality_rationale','')}", styles["body"]),
        Paragraph(f"<b>Notification status:</b> {v.get('notification_status','?')}", styles["body"]),
        Spacer(1, 4 * mm),
    ]


def _pdf_data_quality(document: dict, styles: dict) -> list:
    issues = (document.get("data_quality") or {}).get("issues") or []
    if not issues:
        return []
    out = [Paragraph("Data Quality Issues", styles["h2"])]
    for i in issues:
        sev = i.get("severity", "warning")
        out.append(Paragraph(
            f"<b>[{sev.upper()}]</b> <code>{i.get('code','')}</code> — {i.get('message','')}",
            styles["warning"],
        ))
    out.append(Spacer(1, 4 * mm))
    return out


def _pdf_render_section(sec_id: str, title: str, section: dict,
                        computed: Any, styles: dict) -> list:
    flow: list = [Paragraph(title, styles["h2"])]
    if section.get("v1_status") == "STUB":
        flow.append(Paragraph("(v1 stub — full content available in v2)", styles["stub"]))
    if section.get("build_error"):
        err = section["build_error"]
        flow.append(Paragraph(
            f"<b>Section build error:</b> {err.get('exception_class','?')} — "
            f"{err.get('message','')}", styles["warning"]))
        return flow

    if computed is None:
        flow.append(Paragraph("(no auto output)", styles["stub"]))
        return flow

    if sec_id == "s3_control_failures":
        flow.extend(_pdf_s3(computed, styles))
    elif sec_id == "s6_regulatory_clocks":
        flow.extend(_pdf_s6(computed, styles))
    elif sec_id == "s7_corrective_actions":
        flow.extend(_pdf_s7(computed, styles))
    elif sec_id == "s1_incident_lifecycle":
        flow.extend(_pdf_s1(computed, styles))
    else:
        # Generic fallback — JSON-ish prose
        flow.append(Paragraph(_short_json(computed), styles["body"]))

    overrides = section.get("overrides") or []
    if overrides:
        flow.append(Spacer(1, 2 * mm))
        flow.append(Paragraph(f"{len(overrides)} human edit(s) applied",
                              styles["small"]))
    signoff = section.get("signoff")
    if signoff:
        flow.append(Paragraph(
            f"Signed by {signoff.get('signed_by','?')} at {signoff.get('signed_at','?')}",
            styles["small"]))
    return flow


def _pdf_s1(c: dict, styles: dict) -> list:
    flow: list = [Paragraph("Detect", styles["h3"])]
    detect = c.get("detect") or {}
    flow.append(Paragraph(
        f"Method: {detect.get('method','?')} • Reference: {detect.get('reference','-')}<br/>"
        f"Discovered: {detect.get('detected_at','?')} • First evidence: {detect.get('first_evidence_at','?')}<br/>"
        f"Detection lag: {detect.get('detection_lag_human','?')} • "
        f"Channel: {detect.get('discovery_channel','?')}",
        styles["body"]))

    timeline = c.get("timeline") or []
    if timeline:
        flow.append(Spacer(1, 2 * mm))
        flow.append(Paragraph("Timeline", styles["h3"]))
        rows = [["Time", "Phase", "Event", "Refs"]]
        for t in timeline[:30]:
            rows.append([
                str(t.get("ts", ""))[:19],
                str(t.get("phase", "") or "-"),
                str(t.get("event", ""))[:60],
                ", ".join(str(r) for r in (t.get("evidence_refs") or []))[:20],
            ])
        flow.append(_make_table(rows, col_widths=[35*mm, 25*mm, 90*mm, 25*mm]))
    return flow


def _pdf_s3(c: dict, styles: dict) -> list:
    summary = c.get("summary") or {}
    flow = [Paragraph(
        f"<b>{summary.get('failed_control_count',0)}</b> failed controls — "
        f"<b>{summary.get('critical_control_count',0)}</b> critical — across "
        f"{summary.get('framework_count',0)} frameworks",
        styles["body"])]

    flat = c.get("flat_list") or []
    if flat:
        rows = [["Sev", "Framework", "Control", "Failure", "Triggered by"]]
        for r in flat[:50]:
            rows.append([
                r.get("severity", "")[:8],
                r.get("framework", "")[:14],
                f"{r.get('control_id','')} {r.get('control_name','')[:30]}"[:48],
                r.get("failure_type", "")[:18],
                ", ".join(r.get("triggered_by") or [])[:20],
            ])
        flow.append(_make_table(rows, col_widths=[15*mm, 25*mm, 65*mm, 35*mm, 35*mm]))

    asks = c.get("auditor_asks") or []
    if asks:
        flow.append(Spacer(1, 2 * mm))
        flow.append(Paragraph("Likely auditor questions", styles["h3"]))
        for q in asks:
            flow.append(Paragraph(f"• {q}", styles["body"]))
    return flow


def _pdf_s6(c: dict, styles: dict) -> list:
    flow: list = [Paragraph(
        c.get("human_submit_only_notice", ""), styles["warning"])]
    triggers = c.get("triggers") or []
    if not triggers:
        flow.append(Paragraph("No regulatory triggers fired.", styles["body"]))
        return flow
    rows = [["Regulator", "Clock", "Deadline", "Hours left", "Rationale"]]
    for t in triggers:
        rows.append([
            t.get("regulator", "")[:12],
            t.get("clock_human", "")[:8],
            str(t.get("deadline", ""))[:19],
            str(t.get("hours_remaining", "")),
            (t.get("rationale", "") or "")[:60],
        ])
    flow.append(_make_table(rows, col_widths=[25*mm, 15*mm, 35*mm, 20*mm, 80*mm]))
    return flow


def _pdf_s7(c: dict, styles: dict) -> list:
    actions = c.get("actions") or []
    if not actions:
        return [Paragraph("(no corrective actions)", styles["body"])]
    rows = [["Pri", "Title", "Owner role", "Due (d)", "Frameworks"]]
    for a in actions:
        rows.append([
            a.get("priority", "")[:4],
            a.get("title", "")[:50],
            a.get("owner_role", "")[:25],
            str(a.get("due_days", "?")),
            ", ".join(a.get("framework_refs") or [])[:30],
        ])
    return [_make_table(rows, col_widths=[12*mm, 70*mm, 35*mm, 15*mm, 45*mm])]


def _pdf_evidence_provenance(document: dict, styles: dict) -> list:
    ev = document.get("evidence_provenance") or {}
    refs = ev.get("evidence_row_indices") or []
    return [
        Paragraph("Evidence Provenance", styles["h2"]),
        Paragraph(f"Row count: {ev.get('row_count', len(refs))}", styles["body"]),
        Paragraph(f"Content hash: {ev.get('evidence_content_hash','?')}",
                  styles["small"]),
        Paragraph(f"Row indices (first 100): {', '.join(str(r) for r in refs[:100])}",
                  styles["small"]),
    ]


def _make_table(rows: list[list[str]], col_widths: list[float]) -> Any:
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 7.5),
        ("LEADING",    (0, 0), (-1, -1), 9),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
        ("GRID",       (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f3f4f6")]),
    ]))
    return t


def _pdf_header_footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#666"))
    canvas.drawString(18 * mm, 12 * mm,
                      "JanuSec Postmortem — confidential — do not redistribute")
    canvas.drawRightString(doc.pagesize[0] - 18 * mm, 12 * mm,
                           f"Page {doc.page}")
    canvas.restoreState()


def _short_json(obj: Any) -> str:
    """Convert dict to a short readable string for fallback rendering."""
    import json
    try:
        if isinstance(obj, dict):
            keys = list(obj.keys())[:10]
            parts = []
            for k in keys:
                v = obj[k]
                if isinstance(v, (list, dict)):
                    parts.append(f"<b>{k}:</b> ({type(v).__name__}, {len(v)})")
                else:
                    parts.append(f"<b>{k}:</b> {str(v)[:80]}")
            return "<br/>".join(parts)
        return json.dumps(obj, default=str)[:1000]
    except Exception:
        return str(obj)[:1000]


__all__ = ["render_postmortem_pdf"]
