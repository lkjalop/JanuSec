"""
Compliance One-Pager Renderer
==============================

Single-page PDF showing only the compliance-relevant sections:
  - Section 3: Control failures summary (counts only, not per-row)
  - Section 6: Regulatory clocks (deadlines table)
  - Section 7: Corrective actions (priority + title only)

Use case: Customer's CISO walks into a board meeting and needs ONE PAGE
that says "this is the regulatory exposure, this is what we're doing."
Not the full forensic record.
"""
from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    )
    _REPORTLAB_AVAILABLE = True
except ImportError:
    _REPORTLAB_AVAILABLE = False


def render_compliance_one_pager(*, document: dict, out_path: str) -> str:
    """Render a single-page compliance summary."""
    if not _REPORTLAB_AVAILABLE:
        raise RuntimeError("reportlab not installed")

    from src.postmortem.postmortem_assembler import get_computed_section

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    doc = SimpleDocTemplate(
        out_path,
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=f"JanuSec Compliance One-Pager {document.get('postmortem_id','?')}",
    )

    base = getSampleStyleSheet()
    styles = {
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontSize=14, spaceAfter=4),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=11, spaceAfter=2),
        "body": ParagraphStyle("body", parent=base["BodyText"], fontSize=8, leading=10),
        "small": ParagraphStyle("small", parent=base["BodyText"], fontSize=7,
                                leading=9, textColor=colors.HexColor("#666")),
        "warning": ParagraphStyle("warning", parent=base["BodyText"], fontSize=8,
                                  leading=10, backColor=colors.HexColor("#fff8dc"),
                                  borderPadding=2),
    }

    flow: list = []

    # Header
    pm_id = document.get("postmortem_id", "?")
    cluster_id = document.get("cluster_id", "?")
    verdict = document.get("verdict") or {}
    flow.append(Paragraph("Compliance One-Pager", styles["h1"]))
    flow.append(Paragraph(
        f"<b>Postmortem:</b> {pm_id} • <b>Cluster:</b> {cluster_id} • "
        f"<b>Verdict:</b> {verdict.get('platform_verdict','?')} "
        f"({verdict.get('confidence',0.0):.2f}) • "
        f"<b>Materiality:</b> {verdict.get('materiality_assessment','?')}",
        styles["body"]))
    flow.append(Spacer(1, 3 * mm))

    # ── S3: Control failure summary (one block, no per-row table) ─────────
    s3 = get_computed_section(document, "s3_control_failures") or {}
    summary3 = s3.get("summary") or {}
    flow.append(Paragraph("Control Failures", styles["h2"]))
    flow.append(Paragraph(
        f"<b>{summary3.get('failed_control_count',0)}</b> failed controls — "
        f"<b>{summary3.get('critical_control_count',0)}</b> critical — "
        f"across {', '.join(summary3.get('frameworks_with_failures') or [])}",
        styles["body"]))
    flow.append(Spacer(1, 2 * mm))

    # ── S6: Regulatory clocks ─────────────────────────────────────────────
    s6 = get_computed_section(document, "s6_regulatory_clocks") or {}
    triggers = s6.get("triggers") or []
    flow.append(Paragraph("Regulatory Notification Clocks", styles["h2"]))
    if triggers:
        rows = [["Regulator", "Clock", "Deadline", "Hours left", "Status"]]
        for t in triggers:
            status = "OVERDUE" if t.get("overdue") else "READY FOR HUMAN SUBMISSION"
            rows.append([
                t.get("regulator", "")[:14],
                t.get("clock_human", "")[:6],
                str(t.get("deadline", ""))[:19],
                str(t.get("hours_remaining", "")),
                status[:32],
            ])
        flow.append(_oneliner_table(rows, col_widths=[28*mm, 14*mm, 38*mm, 18*mm, 60*mm]))
    else:
        flow.append(Paragraph("No regulatory triggers fired.", styles["body"]))
    flow.append(Spacer(1, 2 * mm))

    # ── S7: Corrective actions (priority + title only) ────────────────────
    s7 = get_computed_section(document, "s7_corrective_actions") or {}
    actions = s7.get("actions") or []
    flow.append(Paragraph("Corrective Actions", styles["h2"]))
    if actions:
        rows = [["Pri", "Title", "Owner role", "Due (d)"]]
        for a in actions[:12]:    # cap to fit on one page
            rows.append([
                a.get("priority", "")[:4],
                a.get("title", "")[:60],
                a.get("owner_role", "")[:25],
                str(a.get("due_days", "?")),
            ])
        flow.append(_oneliner_table(rows, col_widths=[10*mm, 100*mm, 35*mm, 15*mm]))
        if len(actions) > 12:
            flow.append(Paragraph(f"...and {len(actions) - 12} more (see full report)",
                                  styles["small"]))
    else:
        flow.append(Paragraph("(no corrective actions)", styles["body"]))
    flow.append(Spacer(1, 2 * mm))

    # Footer warning
    flow.append(Paragraph(
        "JanuSec NEVER auto-submits to a regulator. All notifications shown "
        "above require human review and submission via the regulator's "
        "official channel. This one-pager is a summary — see the full "
        "postmortem for evidence references and field-level provenance.",
        styles["warning"]))

    doc.build(flow)
    return out_path


def _oneliner_table(rows: list[list[str]], col_widths: list[float]) -> Any:
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 7),
        ("LEADING",    (0, 0), (-1, -1), 8.5),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
        ("GRID",       (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
    ]))
    return t


__all__ = ["render_compliance_one_pager"]
