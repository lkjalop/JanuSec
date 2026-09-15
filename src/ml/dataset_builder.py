"""Dataset Builder (M2)

Collects calibration samples from in-memory stores and exports in CSV/HTML formats.
Intended for quick offline analysis and as a foundation for training pipelines.
"""
from __future__ import annotations

from typing import List, Dict, Any, Tuple
import csv
import io
import html
import os
from core.redaction import scrub_text
from core.factor_attribution_store import FACTOR_ATTRIBUTIONS, FactorAttributionSnapshot
from core.labels_store import LABELS


def collect_calibration_rows(limit: int = 2000) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    qualifying = {"tp", "fp", "benign"}
    for snap in FACTOR_ATTRIBUTIONS.recent(limit * 2):
        labels = LABELS.get(snap.event_id)
        lab = None
        for l in reversed(labels):
            if l.label in qualifying:
                lab = l.label
                break
        if not lab:
            continue
        top_factors = ",".join(snap.factors[:5]) if snap.factors else ""
        rows.append({
            "event_id": snap.event_id,
            "ts": snap.ts,
            "score": snap.score,
            "raw_score": snap.raw_score if snap.raw_score is not None else snap.score,
            "label": lab,
            "top_factors": top_factors,
        })
        if len(rows) >= limit:
            break
    return rows


def to_csv(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        # ensure header
        rows = [{"event_id": "", "ts": 0.0, "score": 0.0, "raw_score": 0.0, "label": "", "top_factors": ""}]
    # Optional export scrubbing
    if os.getenv('PII_SCRUB_EXPORTS','0').lower() in {'1','true','yes'}:
        for r in rows:
            try:
                if 'event_id' in r and isinstance(r['event_id'], str):
                    r['event_id'] = scrub_text(r['event_id'])
                if 'top_factors' in r and isinstance(r['top_factors'], str):
                    r['top_factors'] = scrub_text(r['top_factors'])
            except Exception:
                continue
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["event_id", "ts", "score", "raw_score", "label", "top_factors"], extrasaction='ignore')
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    return buf.getvalue()


def to_html(rows: List[Dict[str, Any]]) -> str:
    # Optional export scrubbing
    if os.getenv('PII_SCRUB_EXPORTS','0').lower() in {'1','true','yes'}:
        scrubbed: List[Dict[str, Any]] = []
        for r in rows:
            try:
                rr = dict(r)
                if 'event_id' in rr and isinstance(rr['event_id'], str):
                    rr['event_id'] = scrub_text(rr['event_id'])
                if 'top_factors' in rr and isinstance(rr['top_factors'], str):
                    rr['top_factors'] = scrub_text(rr['top_factors'])
                scrubbed.append(rr)
            except Exception:
                scrubbed.append(r)
        rows = scrubbed
    # minimal sortable table
    head = """
<!doctype html>
<html><head><meta charset="utf-8"><title>Calibration Dataset Export</title>
<style>
table{border-collapse:collapse;width:100%;font-family:sans-serif;font-size:14px}
th,td{border:1px solid #ccc;padding:6px 8px}
th{background:#f6f6f6;text-align:left}
code{background:#f2f2f2;padding:2px 4px;border-radius:3px}
</style></head><body>
<h2>Calibration Dataset Export</h2>
<p>Rows: %d</p>
<table><thead><tr>
<th>event_id</th><th>ts</th><th>score</th><th>raw_score</th><th>label</th><th>top_factors</th>
</tr></thead><tbody>
""" % (len(rows),)
    body = []
    for r in rows:
        body.append(
            "<tr><td>%s</td><td>%s</td><td>%.4f</td><td>%.4f</td><td>%s</td><td><code>%s</code></td></tr>" % (
                html.escape(str(r.get("event_id", ""))),
                html.escape(str(r.get("ts", ""))),
                float(r.get("score", 0.0)),
                float(r.get("raw_score", r.get("score", 0.0))),
                html.escape(str(r.get("label", ""))),
                html.escape(str(r.get("top_factors", ""))),
            )
        )
    tail = """
</tbody></table>
</body></html>
"""
    return head + "\n".join(body) + tail


__all__ = ["collect_calibration_rows", "to_csv", "to_html"]
