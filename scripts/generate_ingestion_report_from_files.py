#!/usr/bin/env python3
"""
Generate an ingestion report from one or more CSV/Excel files using the platform's
existing tabular upload and report aggregation pipeline, without running the server.

Outputs JSON, CSV, HTML, and PDF artifacts under artifacts/reports/<timestamp>/.

Usage (Windows PowerShell):
  .\.venv-1\Scripts\python.exe scripts\generate_ingestion_report_from_files.py \
    -o artifacts\reports \
    "D:\\AI\\Threat_thy_sniffer\\dump\\Cyberstash_csv2.xlsx" "D:\\AI\\Threat_thy_sniffer\\dump\\cybstash csv1.xlsx"
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path


def _add_src_to_path() -> None:
    # Ensure we can import platform modules when invoked as a standalone script
    this = Path(__file__).resolve()
    repo_root = this.parents[1]
    src_dir = repo_root / 'src'
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))


def _ts_dir(base: Path) -> Path:
    ts = time.strftime('%Y%m%d_%H%M%S')
    out_dir = base / ts
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def main() -> int:
    _add_src_to_path()
    parser = argparse.ArgumentParser(description='Generate ingestion report from CSV/Excel files')
    parser.add_argument('files', nargs='+', help='Paths to CSV/XLSX/XLS files')
    parser.add_argument('-o', '--out', default='artifacts/reports', help='Output base directory (default: artifacts/reports)')
    parser.add_argument('--include-alerts', action='store_true', help='Include recent alerts in the report (requires running state)')
    parser.add_argument('--alerts-limit', type=int, default=150, help='Max alerts to include when --include-alerts is set (default: 150)')
    parser.add_argument('--no-exec-summary', action='store_true', help='Skip generating executive summary PDF')
    args = parser.parse_args()

    # Lazy imports after path setup
    from api.upload_endpoints import ExcelProcessor, CSVProcessor, _maybe_create_tabular_session, TABULAR_SESSIONS  # type: ignore
    from api.report_aggregation import build_ingestion_report  # type: ignore
    import api.report_endpoints as rep  # type: ignore

    # Prepare processors
    excel = ExcelProcessor()
    csvp = CSVProcessor()

    session_ids: list[str] = []
    processed: list[dict] = []

    for f in args.files:
        p = Path(f)
        if not p.exists():
            print(f"[WARN] File not found: {p}")
            continue
        try:
            content = p.read_bytes()
        except Exception as e:
            print(f"[WARN] Failed to read {p}: {e}")
            continue

        # Choose processor based on extension
        ext = p.suffix.lower()
        try:
            if ext in {'.xlsx', '.xls'}:
                res = asyncio_run(excel.process(p.name, content))
            elif ext == '.csv':
                res = asyncio_run(csvp.process(p.name, content))
            else:
                # Best-effort: try Excel first, then CSV
                try:
                    res = asyncio_run(excel.process(p.name, content))
                except Exception:
                    res = asyncio_run(csvp.process(p.name, content))
        except Exception as e:
            print(f"[WARN] Processing failed for {p}: {e}")
            continue

        processed.append({'file': str(p), 'result': res})
        analysis = res.get('analysis', {}) if isinstance(res, dict) else {}
        sid = analysis.get('pagination_session')
        # If no session was created (small files), force-create one so it shows in the report
        if not sid:
            try:
                headers = analysis.get('headers') or []
                totals = (analysis.get('suspicious_patterns') or {}).get('totals') if analysis.get('suspicious_patterns') else {}
                # Attempt to pass the patterns so rollup reflects this file
                patterns = analysis.get('suspicious_patterns') or {'totals': totals or {}}
                sid = _maybe_create_tabular_session(
                    original_filename=p.name,
                    file_type='excel' if ext in {'.xlsx', '.xls'} else 'csv',
                    headers=headers,
                    total_rows=int(analysis.get('row_count_estimate') or analysis.get('row_count') or 0),
                    store_bytes=content,
                    mode='excel' if ext in {'.xlsx', '.xls'} else 'csv',
                    sheet_name=analysis.get('sheet_name') if ext in {'.xlsx', '.xls'} else None,
                    patterns=patterns,
                )
            except Exception:
                sid = None
        if sid:
            session_ids.append(sid)

    if not session_ids:
        print("[ERROR] No sessions created from provided files; cannot build report.")
        return 2

    # Build report (without alerts unless explicitly requested)
    include_alerts = bool(args.include_alerts)
    state = None  # not needed unless include_alerts is True
    try:
        report = build_ingestion_report(session_ids, include_alerts, int(args.alerts_limit), state, tenant_id=None, alerts_offset=0, include_scenarios=False, include_model=True)
    except TypeError:
        # If a stricter signature is enforced, call with only mandatory args
        report = build_ingestion_report(session_ids, include_alerts, int(args.alerts_limit), state)

    out_base = Path(args.out)
    out_dir = _ts_dir(out_base)

    # Write JSON
    json_path = out_dir / 'ingestion_report.json'
    json_path.write_text(json.dumps(report, indent=2), encoding='utf-8')

    # Write CSV
    try:
        csv_bytes = rep._render_csv(report)  # type: ignore[attr-defined]
        (out_dir / 'ingestion_report.csv').write_bytes(csv_bytes)
    except Exception as e:
        print(f"[WARN] CSV render failed: {e}")

    # Write HTML
    try:
        html_text = rep._render_html(report)  # type: ignore[attr-defined]
        (out_dir / 'ingestion_report.html').write_text(html_text, encoding='utf-8')
    except Exception as e:
        print(f"[WARN] HTML render failed: {e}")

    # Write PDF (ingestion_report.pdf) if reportlab available
    try:
        pdf_bytes = rep._render_pdf(report)  # type: ignore[attr-defined]
        (out_dir / 'ingestion_report.pdf').write_bytes(pdf_bytes)
    except Exception as e:
        print(f"[WARN] PDF render failed (reportlab missing?): {e}")

    # Optional: Executive Summary PDF for non-technical audience
    if not args.no_exec_summary:
        try:
            from reportlab.lib.pagesizes import LETTER  # type: ignore
            from reportlab.lib.styles import getSampleStyleSheet  # type: ignore
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer  # type: ignore
            from reportlab.lib import colors  # type: ignore
            exec_path = out_dir / 'ingestion_executive_summary.pdf'
            buf = SimpleDocTemplate(str(exec_path), pagesize=LETTER, leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=40)
            styles = getSampleStyleSheet()
            story = []
            ts_fmt = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(report.get('generated_at',0))) + ' UTC'
            story.append(Paragraph('<b>Executive Summary: Ingestion Assessment</b>', styles['Title']))
            story.append(Paragraph(f'Generated: {ts_fmt}', styles['Normal']))
            story.append(Spacer(1, 10))
            # Scope
            sources = report.get('source_files', []) or []
            story.append(Paragraph('<b>Scope</b>', styles['Heading3']))
            story.append(Paragraph(f"Analyzed {len(sources)} tabular files with {sum(int(s.get('total_rows') or 0) for s in sources)} rows in total.", styles['Normal']))
            if sources:
                names = ', '.join([str(s.get('filename') or s.get('session') or '') for s in sources])
                story.append(Paragraph(f"Files: {names}", styles['Normal']))
            story.append(Spacer(1, 8))
            # Key Findings (non-technical)
            roll = report.get('suspicious_patterns_rollup', {}) or {}
            susp = int(roll.get('suspicious_cells') or 0)
            b64 = int(roll.get('base64_matches') or 0)
            ps  = int(roll.get('powershell_matches') or 0)
            story.append(Paragraph('<b>Key Findings</b>', styles['Heading3']))
            if susp == 0:
                story.append(Paragraph('No suspicious textual patterns were detected in the sampled rows. Environment appears stable.', styles['Normal']))
            else:
                story.append(Paragraph(f'Detected {susp} suspicious cells in textual content. Indicators include {b64} hash/base64-like strings and {ps} PowerShell-encoded markers.', styles['Normal']))
            sev = report.get('severity_distribution', {}) or {}
            sev_txt = ', '.join([f"{k}: {v}" for k,v in sev.items()]) if sev else 'No event severities available in offline run.'
            story.append(Paragraph(f'Severity distribution (from recent decisions if available): {sev_txt}', styles['Normal']))
            story.append(Spacer(1, 8))
            # Framework Mapping (explanatory, non-technical)
            story.append(Paragraph('<b>Framework Mapping (Explainability)</b>', styles['Heading3']))
            story.append(Paragraph('When events are flagged in live operation, we summarize risks using standard models:', styles['Normal']))
            story.append(Paragraph('- MITRE ATT&CK: technique tags observed in detection factors', styles['Normal']))
            story.append(Paragraph('- STRIDE: threat categories to communicate “what type of risk”', styles['Normal']))
            story.append(Paragraph('- DREAD & MAESTRO: composite impact/likelihood indicators for prioritization', styles['Normal']))
            story.append(Paragraph('- PASTA: scenario lens for attacker goals and defensive countermeasures', styles['Normal']))
            story.append(Spacer(1, 8))
            # Recommendations (business)
            recs = report.get('recommendations', []) or []
            story.append(Paragraph('<b>Recommendations</b>', styles['Heading3']))
            if recs:
                for r in recs:
                    story.append(Paragraph(f'- {r}', styles['Normal']))
            else:
                story.append(Paragraph('- Environment appears stable; continue baseline monitoring.', styles['Normal']))
            # Next steps for analysts
            story.append(Spacer(1, 8))
            story.append(Paragraph('<b>Operational Next Steps</b>', styles['Heading3']))
            next_steps = [
                'Enable live stream with production telemetry to populate factor-driven flags and MITRE mapping.',
                'Create suppression rules for benign repetitive patterns to reduce alert noise.',
                'Review any base64/hash-like content for provenance; quarantine unknown binaries until approved.',
                'If PowerShell markers appear, assess encoded command sources and enforce application control.',
            ]
            for n in next_steps:
                story.append(Paragraph(f'- {n}', styles['Normal']))
            buf.build(story)
        except Exception as e:
            print(f"[WARN] Executive summary PDF generation skipped: {e}")

    # Best-effort manifest
    manifest = {
        'generated_at': time.time(),
        'sessions': session_ids,
        'files': [str(p) for p in args.files],
        'output_dir': str(out_dir),
        'artifacts': [
            str(json_path),
            str(out_dir / 'ingestion_report.csv'),
            str(out_dir / 'ingestion_report.html'),
            str(out_dir / 'ingestion_report.pdf'),
            str(out_dir / 'ingestion_executive_summary.pdf'),
        ],
    }
    (out_dir / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')

    print("Report generated:")
    print("  ", json_path)
    if (out_dir / 'ingestion_report.csv').exists():
        print("  ", out_dir / 'ingestion_report.csv')
    if (out_dir / 'ingestion_report.html').exists():
        print("  ", out_dir / 'ingestion_report.html')
    return 0


def asyncio_run(coro):
    """Run an async coroutine in a fresh event loop for scripts.

    This avoids conflicts if the script is called from environments where an
    event loop may already be running.
    """
    try:
        import asyncio
        try:
            # If there's an existing loop, create a new one to run our task
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(coro)
            finally:
                try:
                    loop.close()
                except Exception:
                    pass
        except Exception:
            return asyncio.get_event_loop().run_until_complete(coro)
    except Exception as e:
        raise e


if __name__ == '__main__':
    sys.exit(main())
