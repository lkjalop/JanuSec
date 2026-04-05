"""Offline executive report generator for Azure/AWS test packs."""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Set env before any app imports.
# LLM_MOCK: default OFF so Ollama/real LLM is used when available.
# Set LLM_MOCK=1 in your environment to force offline mock generation.
os.environ.setdefault("LLM_MOCK", "0")
# Use a local SQLite DB by default instead of disabling the DB entirely.
os.environ.setdefault("JANUSEC_SQLITE_PATH", "data/janusec.db")
os.environ.setdefault("API_KEYS_JSON", '[{"key":"devkey123","scopes":["*"]}]')

repo_root = Path(__file__).resolve().parents[1]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from scripts.offline_replay_harness import _load_rows
from src.analysis.offline_workbook_assessment import build_offline_workbook_assessment
from src.reporting.executive_reporting import build_executive_report_artifact, render_executive_report_html, build_executive_filename
from src.reporting.export import export_pdf_bytes_from_html


def generate(pack_path: str, org: str, out_dir: str):
    print(f"\n=== {org} ===")
    rows = _load_rows(Path(pack_path))
    print(f"  Loaded {len(rows)} rows")

    assessment = build_offline_workbook_assessment(
        rows,
        assessment_id=Path(pack_path).name + "-live",
        org=org,
        auto_llm=True,
    )
    print(f"  Assessment built: {assessment.get('assessment_id')}")

    artifact = build_executive_report_artifact(
        assessment,
        {
            "timeframe": "24h",
            "selection_mode": "selected_key_alerts",
            "include_overview": True,
            "include_claims": True,
            "include_selected_alerts": True,
            "include_review_state_chart": True,
            "include_trends": True,
            "include_appendix": True,
            "include_framework_sections": True,
        },
    )

    html = render_executive_report_html(artifact)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    html_name = build_executive_filename(artifact, "html")
    pdf_name = build_executive_filename(artifact, "pdf")
    html_path = out / html_name
    pdf_path = out / pdf_name

    html_path.write_text(html, encoding="utf-8")
    print(f"  HTML -> {html_path}")

    pdf_bytes = export_pdf_bytes_from_html(html)
    if pdf_bytes:
        pdf_path.write_bytes(pdf_bytes)
        print(f"  PDF  -> {pdf_path}")
    else:
        print("  PDF: WeasyPrint not available (HTML only)")

    return str(html_path), str(pdf_path) if pdf_bytes else None


if __name__ == "__main__":
    generate(
        "dump/tests/janusec_test_packs/azure_contoso_dev",
        "contoso.dev",
        "artifacts/reports/executive_review/azure",
    )
    generate(
        "dump/tests/janusec_test_packs/aws_123456789012",
        "123456789012",
        "artifacts/reports/executive_review/aws",
    )
    print("\nDone.")
