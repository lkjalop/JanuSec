from __future__ import annotations

from pathlib import Path


FIXTURE_DIR = Path("dump/test files")


def test_santos_enrichment_workbook_is_not_production_evidence():
    """The Santos enrichment workbook is an evaluation/context answer key.

    It may be used by an offline scoring harness, but production assessment
    hydration must not convert it into breach cases.
    """
    from src.core.ingest.file_parser import parse_file
    from src.core.ingest.input_classifier import classify_xlsx_path

    workbook = FIXTURE_DIR / "janusec_enrichment_context_v1.xlsx"
    classification = classify_xlsx_path(workbook, filename=workbook.name)

    assert classification["lane"] == "evaluation_answer_key"
    assert classification["evidence_allowed"] is False
    assert list(parse_file(str(workbook), filename=workbook.name)) == []

