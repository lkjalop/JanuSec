#!/usr/bin/env python3
"""
Offline multi-persona report regenerator.
Processes janusec_test_01_benign.xlsx, janusec_test_02_medium.xlsx,
janusec_test_03_critical.xlsx through the v3 engine (no server required),
writes outputs to dump/reports/Cloud-post-fixes/, and produces a
side-by-side comparison JSON vs. dump/reports/Cloud-new/_comparison.json.

Usage:
    .\.venv\Scripts\python.exe scripts\regenerate_test_reports.py
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# ── Environment setup (must be first) ─────────────────────────────────────
os.environ.setdefault("LLM_MOCK", "1")         # no Ollama needed
os.environ.setdefault("DISABLE_DB", "1")
os.environ.setdefault("PLATFORM_LITE_INIT", "1")
os.environ.setdefault("TEST_HELPERS_ENABLED", "1")
os.environ.setdefault("API_KEYS_JSON", '[{"key":"devkey123","scopes":["*"]}]')
os.environ.setdefault("JANUSEC_SQLITE_PATH", "data/janusec_reports.db")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# ── Config ─────────────────────────────────────────────────────────────────
XLSX_FILES = [
    ROOT / "dump" / "janusec_test_01_benign.xlsx",
    ROOT / "dump" / "janusec_test_02_medium.xlsx",
    ROOT / "dump" / "janusec_test_03_critical.xlsx",
]
XLSX_FILES_V2 = [
    ROOT / "dump" / "janusec_test_01_benign_v2.xlsx",
    ROOT / "dump" / "janusec_test_02_medium_v2.xlsx",
    ROOT / "dump" / "janusec_test_03_critical_v2.xlsx",
]
PERSONAS = ["executive", "ciso", "soc_analyst", "threat_hunter", "forensics", "compliance", "audit", "mssp"]
OUT_DIR  = ROOT / "dump" / "reports" / "Cloud-post-fixes"
OUT_DIR_V2 = ROOT / "dump" / "reports" / "Cloud-v2"
BASELINE = ROOT / "dump" / "reports" / "Cloud-new" / "_comparison.json"


# ── Lazy imports (after env vars set) ─────────────────────────────────────
def _import_pipeline():
    # Import _load_xlsx_rows directly from its underlying module to avoid
    # offline_replay_harness pulling in fastapi.testclient before the app loads
    import sys, importlib, types
    # Inline the xlsx loader rather than importing the full harness
    try:
        from scripts.offline_replay_harness import _load_xlsx_rows  # type: ignore
    except Exception:
        # Fallback: define a minimal xlsx loader that doesn't require fastapi
        try:
            import openpyxl
        except ImportError:
            raise ImportError("openpyxl is required: pip install openpyxl")

        def _load_xlsx_rows(path):  # type: ignore[override]
            wb = openpyxl.load_workbook(str(path), read_only=True, data_only=True)
            rows = []
            for sheet_name in wb.sheetnames:
                ws = wb[sheet_name]
                all_rows = list(ws.iter_rows(values_only=True))
                if not all_rows:
                    continue
                headers = [str(h or f"col{i}").strip() for i, h in enumerate(all_rows[0])]
                for idx, row in enumerate(all_rows[1:]):
                    # Preserve None as None; don't coerce to "" since empty strings
                    # can trigger false-positive cross-sheet indicator pivots in scoring.
                    rec = {headers[i]: v for i, v in enumerate(row) if v is not None}
                    rec["row_index"] = idx
                    rec["_sheet"] = sheet_name
                    rec["sheet"] = sheet_name
                    rec["source_file"] = path.name
                    rec["fingerprint"] = f"{path.name}:{sheet_name}:{idx}"
                    rows.append(rec)
            return rows

    from src.analysis.offline_workbook_assessment import build_offline_workbook_assessment
    from src.reporting.executive_reporting import (
        build_executive_report_artifact,
        render_executive_report_html,
    )
    try:
        from src.reporting.export import export_pdf_bytes_from_html
    except Exception:
        export_pdf_bytes_from_html = None  # type: ignore
    return (_load_xlsx_rows, build_offline_workbook_assessment,
            build_executive_report_artifact, render_executive_report_html,
            export_pdf_bytes_from_html)


def _extract_summary(artifact: dict, persona: str, xlsx_name: str) -> dict:
    """Pull the key comparison fields from an artifact."""
    # Correct field paths (verified against actual artifact structure):
    # headline         → artifact['overview']['headline']
    # stakeholder_gate → artifact['overview']['stakeholder_gate']
    # claim_register   → artifact['appendix']['evidence_appendix']['claim_register']
    #                    or artifact['facts']['claim_register']
    # source_rows      → artifact['appendix']['evidence_appendix']['source_rows']
    # review_counts    → artifact['facts']['review_state_counts']
    overview  = artifact.get("overview") or {}
    facts     = artifact.get("facts") or {}
    ev_app    = (artifact.get("appendix") or {}).get("evidence_appendix") or {}
    sg        = overview.get("stakeholder_gate") or {}

    headline = overview.get("headline") or overview.get("executive_title") or "—"
    stakeholder_now  = sg.get("stakeholder_now") or []
    stakeholder_wait = sg.get("stakeholder_wait") or []

    # Claims come from evidence_appendix.claim_register (dict with 'claim'+'status' keys)
    claim_reg = ev_app.get("claim_register") or facts.get("claim_register") or []

    confirmed_claims = [
        c.get("claim") for c in claim_reg
        if str(c.get("status") or c.get("confidence_band") or "").lower()
        in ("observed", "likely", "supported", "confirmed")
    ]
    unknown_claims = [
        c.get("claim") for c in claim_reg
        if str(c.get("status") or c.get("confidence_band") or "").lower() == "unknown"
    ]
    # Claim bands: derive from status field (may also be confidence_band in older schemas)
    claim_bands = sorted(set(
        str(c.get("confidence_band") or c.get("status") or "") for c in claim_reg
        if c.get("confidence_band") or c.get("status")
    ))

    source_rows = ev_app.get("source_rows") or ev_app.get("appendix_event_rows") or 0
    top_checks  = len(overview.get("top_3_checks") or [])
    shared_pivots = len(ev_app.get("raw_shared_pivots") or ev_app.get("pivot_entities") or [])
    review_counts = facts.get("review_state_counts") or {}

    return {
        "persona": persona,
        "headline": headline,
        "confirmed_claims": [c for c in confirmed_claims if c][:5],
        "unknown_claims": [c for c in unknown_claims if c][:5],
        "claim_bands": claim_bands,
        "stakeholder_now": stakeholder_now,
        "stakeholder_wait": stakeholder_wait,
        "top_checks": top_checks,
        "shared_pivots": shared_pivots,
        "appendix_event_rows": source_rows,
        "review_state_counts": review_counts,
    }


def _compare_fields(before: dict, after: dict) -> dict:
    """Return a dict of field changes between two summary dicts."""
    changes: dict = {}
    key_fields = [
        "headline", "stakeholder_now", "stakeholder_wait",
        "claim_bands", "appendix_event_rows", "confirmed_claims",
    ]
    for key in key_fields:
        b, a = before.get(key), after.get(key)
        if b != a:
            changes[key] = {"before": b, "after": a}
    return changes


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"\nOutput directory: {OUT_DIR}\n")
    print(f"Processing {len(XLSX_FILES)} xlsx files x {len(PERSONAS)} personas "
          f"= {len(XLSX_FILES)*len(PERSONAS)} reports\n")

    (_load_xlsx_rows, build_offline_workbook_assessment,
     build_executive_report_artifact, render_executive_report_html,
     export_pdf_bytes_from_html) = _import_pipeline()

    # Load baseline comparison (Cloud-new) for diff
    baseline: dict = {}
    if BASELINE.exists():
        try:
            baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        except Exception:
            pass

    comparison_new: dict = {}
    index_entries: list = []

    for xlsx in XLSX_FILES:
        if not xlsx.exists():
            print(f"  [SKIP] Not found: {xlsx}")
            continue

        stem = xlsx.stem  # e.g. "janusec_test_01_benign"
        print(f"{'-'*60}")
        print(f"  {xlsx.name}")
        print(f"{'-'*60}")

        t0 = time.monotonic()

        # 1. Load rows
        try:
            rows = _load_xlsx_rows(xlsx)
        except Exception as exc:
            print(f"  [ERROR] Could not load rows: {exc}")
            continue
        print(f"  Loaded {len(rows)} rows")

        # 2. Build offline assessment (our fixed code path)
        try:
            assessment = build_offline_workbook_assessment(
                rows,
                assessment_id=f"{stem}-post-fixes",
                org=stem,
                auto_llm=True,  # enables Ollama-grounded narrative (mocked when LLM_MOCK=1)
            )
        except Exception as exc:
            print(f"  [ERROR] build_offline_workbook_assessment: {exc}")
            import traceback; traceback.print_exc()
            continue
        print(f"  Assessment: {assessment.get('assessment_id')}")

        file_summaries: dict = {}  # persona → summary

        # 3. Process each persona
        for persona in PERSONAS:
            try:
                options = {
                    "timeframe": "24h",
                    "selection_mode": "selected_key_alerts",
                    "include_overview": True,
                    "include_claims": True,
                    "include_selected_alerts": True,
                    "include_review_state_chart": True,
                    "include_trends": False,
                    "include_appendix": True,
                    "include_framework_sections": True,
                    "persona": persona,
                }
                artifact = build_executive_report_artifact(assessment, options)
                html = render_executive_report_html(artifact)

                # Write HTML
                html_name = f"{stem}-{persona}-v3.html"
                html_path = OUT_DIR / html_name
                html_path.write_text(html, encoding="utf-8")

                # Try PDF export
                pdf_written = False
                if export_pdf_bytes_from_html:
                    try:
                        pdf_bytes = export_pdf_bytes_from_html(html)
                        if pdf_bytes:
                            pdf_path = OUT_DIR / f"{stem}-{persona}-v3.pdf"
                            pdf_path.write_bytes(pdf_bytes)
                            pdf_written = True
                    except Exception:
                        pass

                # Build summary JSON
                summary = _extract_summary(artifact, persona, xlsx.name)
                summary_path = OUT_DIR / f"{stem}-{persona}-v3.summary.json"
                summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

                file_summaries[persona] = summary
                index_entries.append({
                    "file": xlsx.name,
                    "persona": persona,
                    "html": html_name,
                    "pdf": f"{stem}-{persona}-v3.pdf" if pdf_written else None,
                    "headline": summary["headline"],
                })
                status = "HTML+PDF" if pdf_written else "HTML only"
                print(f"    [{persona:15s}]  {status}  — {summary['headline'][:60]}")

            except Exception as exc:
                print(f"    [{persona:15s}]  ERROR: {exc}")
                import traceback; traceback.print_exc()

        # Save per-file comparison
        if file_summaries:
            # Build aggregate (executive persona drives the top-level entry)
            exec_summary = file_summaries.get("executive") or next(iter(file_summaries.values()))
            comparison_new[xlsx.name] = {
                "rows": len(rows),
                "findings": len([r for r in rows if r.get("verdict") in ("malicious", "suspicious")]),
                "headline": exec_summary.get("headline"),
                "confirmed_claims": exec_summary.get("confirmed_claims", []),
                "unknown_claims": exec_summary.get("unknown_claims", []),
                "claim_bands": exec_summary.get("claim_bands", []),
                "stakeholder_now": exec_summary.get("stakeholder_now", []),
                "stakeholder_wait": exec_summary.get("stakeholder_wait", []),
                "top_checks": exec_summary.get("top_checks", 0),
                "appendix_event_rows": exec_summary.get("appendix_event_rows", 0),
                "review_state_counts": exec_summary.get("review_state_counts", {}),
                "per_persona_headlines": {p: s.get("headline") for p, s in file_summaries.items()},
            }

        elapsed = round(time.monotonic() - t0, 1)
        print(f"\n  Done in {elapsed}s\n")

    # Write new comparison JSON
    new_comparison_path = OUT_DIR / "_comparison.json"
    new_comparison_path.write_text(json.dumps(comparison_new, indent=2), encoding="utf-8")
    print(f"Wrote: {new_comparison_path}")

    # Write index JSON
    index_path = OUT_DIR / "_index.json"
    index_path.write_text(json.dumps({"reports": index_entries}, indent=2), encoding="utf-8")
    print(f"Wrote: {index_path}")

    # ── Side-by-side diff vs. Cloud-new ───────────────────────────────────
    _print_diff(baseline, comparison_new)

    # ── v2 xlsx files ────────────────────────────────────────────────────────
    v2_xlsx = [x for x in XLSX_FILES_V2 if x.exists()]
    if v2_xlsx:
        print(f"\n{'='*60}")
        print(f"  Processing {len(v2_xlsx)} v2 xlsx files -> {OUT_DIR_V2.name}")
        print(f"{'='*60}\n")
        comparison_v2, index_v2 = _process_file_batch(
            v2_xlsx, OUT_DIR_V2,
            build_offline_workbook_assessment, build_executive_report_artifact,
            render_executive_report_html, export_pdf_bytes_from_html, _load_xlsx_rows,
        )
        (OUT_DIR_V2 / "_comparison.json").write_text(json.dumps(comparison_v2, indent=2), encoding="utf-8")
        (OUT_DIR_V2 / "_index.json").write_text(json.dumps({"reports": index_v2}, indent=2), encoding="utf-8")
        print(f"\nWrote v2 outputs to {OUT_DIR_V2}")

        # 3-way comparison summary
        _print_3way_comparison(baseline, comparison_new, comparison_v2)
    else:
        print("\n(No v2 xlsx files found — skipping v2 batch)")


def _process_file_batch(
    xlsx_files, out_dir, build_assessment, build_artifact, render_html, export_pdf, load_rows
):
    """Process a batch of xlsx files and return (comparison_dict, index_list)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    comparison: dict = {}
    index_entries: list = []

    for xlsx in xlsx_files:
        stem = xlsx.stem
        print(f"{'-'*60}")
        print(f"  {xlsx.name}")
        print(f"{'-'*60}")
        t0 = time.monotonic()
        try:
            rows = load_rows(xlsx)
        except Exception as exc:
            print(f"  [ERROR] load_rows: {exc}")
            continue
        print(f"  Loaded {len(rows)} rows")
        try:
            assessment = build_assessment(rows, assessment_id=f"{stem}-v2", org=stem, auto_llm=True)  # Ollama-grounded (mocked when LLM_MOCK=1)
        except Exception as exc:
            print(f"  [ERROR] build_assessment: {exc}")
            import traceback; traceback.print_exc()
            continue
        rq = assessment.get("risk_quantification", {})
        print(f"  Severity: {rq.get('severity')} (confidence {rq.get('likelihood_percent', '?')}%)")

        file_summaries: dict = {}
        for persona in PERSONAS:
            try:
                options = {
                    "timeframe": "24h", "selection_mode": "selected_key_alerts",
                    "include_overview": True, "include_claims": True,
                    "include_selected_alerts": True, "include_review_state_chart": True,
                    "include_trends": False, "include_appendix": True,
                    "include_framework_sections": True,
                    "persona": persona,
                }
                artifact = build_artifact(assessment, options)
                html = render_html(artifact)
                html_name = f"{stem}-{persona}-v2.html"
                (out_dir / html_name).write_text(html, encoding="utf-8")

                pdf_written = False
                if export_pdf:
                    try:
                        pdf_bytes = export_pdf(html)
                        if pdf_bytes:
                            (out_dir / f"{stem}-{persona}-v2.pdf").write_bytes(pdf_bytes)
                            pdf_written = True
                    except Exception:
                        pass

                summary = _extract_summary(artifact, persona, xlsx.name)
                (out_dir / f"{stem}-{persona}-v2.summary.json").write_text(
                    json.dumps(summary, indent=2), encoding="utf-8"
                )
                file_summaries[persona] = summary
                index_entries.append({
                    "file": xlsx.name, "persona": persona,
                    "html": html_name,
                    "pdf": f"{stem}-{persona}-v2.pdf" if pdf_written else None,
                    "headline": summary["headline"],
                })
                status = "HTML+PDF" if pdf_written else "HTML"
                print(f"    [{persona:15s}]  {status}  — {summary['headline'][:60]}")
            except Exception as exc:
                print(f"    [{persona:15s}]  ERROR: {exc}")
                import traceback; traceback.print_exc()

        if file_summaries:
            exec_s = file_summaries.get("executive") or next(iter(file_summaries.values()))
            comparison[xlsx.name] = {
                "rows": len(rows),
                "severity": rq.get("severity"),
                "headline": exec_s.get("headline"),
                "confirmed_claims": exec_s.get("confirmed_claims", []),
                "unknown_claims": exec_s.get("unknown_claims", []),
                "claim_bands": exec_s.get("claim_bands", []),
                "stakeholder_now": exec_s.get("stakeholder_now", []),
                "appendix_event_rows": exec_s.get("appendix_event_rows", 0),
                "review_state_counts": exec_s.get("review_state_counts", {}),
                "per_persona_headlines": {p: s.get("headline") for p, s in file_summaries.items()},
            }
        elapsed = round(time.monotonic() - t0, 1)
        print(f"\n  Done in {elapsed}s\n")

    return comparison, index_entries


def _print_3way_comparison(baseline: dict, v1_new: dict, v2_new: dict) -> None:
    """Print a 3-way comparison: Cloud-new (old) vs v1 (fixed) vs v2 (rich data)."""
    print()
    print("=" * 72)
    print("  3-WAY COMPARISON: Cloud-new (old) vs v1-fixed vs v2-new")
    print("=" * 72)
    all_stems = {"benign": None, "medium": None, "critical": None}
    for col_name, col_data in [("Cloud-new (v1 old)", baseline), ("v1-fixed", v1_new), ("v2-new", v2_new)]:
        for fname, fdata in col_data.items():
            stem = "benign" if "benign" in fname else "medium" if "medium" in fname else "critical" if "critical" in fname else None
            if stem:
                if all_stems[stem] is None:
                    all_stems[stem] = {}
                all_stems[stem][col_name] = fdata
    for tier in ("benign", "medium", "critical"):
        print(f"\n  [{tier.upper()}]")
        tier_data = all_stems.get(tier) or {}
        for col_name in ("Cloud-new (v1 old)", "v1-fixed", "v2-new"):
            d = tier_data.get(col_name) or {}
            sev = d.get("severity") or "?"
            hl = (d.get("headline") or "—")[:55]
            rows = d.get("rows", 0)
            ae = d.get("appendix_event_rows", 0)
            print(f"    {col_name:22s}: sev={sev:8s} rows={rows:4d} ev={ae:3d}  {hl}")
    print()

def _print_diff(before: dict, after: dict) -> None:
    """Print a human-readable diff between old (Cloud-new) and new reports."""
    print()
    print("=" * 68)
    print("  BEFORE vs AFTER — Production Gap Fix Validation")
    print("=" * 68)

    all_files = sorted(set(list(before.keys()) + list(after.keys())))
    overall_ok = True

    for fname in all_files:
        b = before.get(fname) or {}
        a = after.get(fname) or {}
        if not a:
            print(f"\n  [SKIP] {fname} — no new data generated")
            continue

        print(f"\n  {fname}")
        print(f"  {'-'*60}")

        checks: list[tuple[str, bool, str, str]] = []

        # P0 Fix 3 — headline should now be tier-differentiated
        b_head = b.get("headline") or "—"
        a_head = a.get("headline") or "—"
        head_changed = b_head != a_head
        checks.append(("P0 Fix 3: Headline tier-aware", head_changed,
                        f"BEFORE: {b_head}", f"AFTER:  {a_head}"))

        # P0 Fix 1 — benign suppressor (test_01 should have fewer 'Supported' bands)
        b_bands = set(b.get("claim_bands") or [])
        a_bands = set(a.get("claim_bands") or [])
        is_benign_file = "benign" in fname.lower()
        if is_benign_file:
            suppressor_ok = "Supported" not in a_bands or a.get("appendix_event_rows", 0) == 0
            checks.append(("P0 Fix 1: Benign suppressor (Supported demoted)",
                           suppressor_ok,
                           f"BEFORE bands: {sorted(b_bands)}",
                           f"AFTER  bands: {sorted(a_bands)}"))

        # P0 Fix 2 — stakeholder escalation for critical/medium should now include CISO/Legal
        b_stake = b.get("stakeholder_now") or []
        a_stake = a.get("stakeholder_now") or []
        is_critical = "critical" in fname.lower()
        is_medium   = "medium" in fname.lower()
        if is_critical:
            stake_ok = any("CISO" in str(s) or "ciso" in str(s).lower() for s in a_stake)
            checks.append(("P0 Fix 2: CISO in stakeholder_now for critical file",
                           stake_ok, f"BEFORE: {b_stake}", f"AFTER:  {a_stake}"))
        elif is_medium:
            medium_stake_ok = len(a_stake) >= len(b_stake)
            checks.append(("P0 Fix 2: Stakeholder list same or expanded for medium",
                           medium_stake_ok, f"BEFORE: {b_stake}", f"AFTER:  {a_stake}"))

        # P1 Fix 4 — source_rows no longer 0
        b_rows = b.get("appendix_event_rows") or 0
        a_rows = a.get("appendix_event_rows") or 0
        rows_fixed = a_rows > 0
        checks.append(("P1 Fix 4: appendix_event_rows no longer 0",
                        rows_fixed, f"BEFORE: {b_rows}", f"AFTER:  {a_rows}"))

        # Print checks
        for label, ok, before_str, after_str in checks:
            status = "PASS" if ok else "FAIL"
            if not ok:
                overall_ok = False
            print(f"    [{status}] {label}")
            print(f"           {before_str}")
            print(f"           {after_str}")

    print()
    print("=" * 68)
    print(f"  RESULT: {'ALL CHECKS PASSED' if overall_ok else 'SOME CHECKS FAILED — review above'}")
    print("=" * 68)
    print()


if __name__ == "__main__":
    main()
