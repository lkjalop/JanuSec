import json
import pytest
from src.core.ingest.file_parser import parse_file, _parse_json_ijson, validate_file_syntax


@pytest.mark.parametrize("suffix", [".json", ".ndjson"])
@pytest.mark.parametrize("bom", [True, False])
def test_json_row_survives_utf8_bom(tmp_path, suffix, bom):
    row = {"title": "No credential dumping occurred", "status": "closed"}
    path = tmp_path / ("negative" + suffix)
    path.write_text(json.dumps(row), encoding="utf-8-sig" if bom else "utf-8")
    validate_file_syntax(str(path), path.name)
    rows = list(parse_file(str(path), filename=path.name))
    assert len(rows) == 1 and rows[0]["title"] == row["title"]


@pytest.mark.parametrize("container", [lambda row: [row], lambda row: {"events": [row]}])
def test_streaming_json_accepts_bom(tmp_path, container):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(container({"event_id": "synthetic"})), encoding="utf-8-sig")
    rows = list(_parse_json_ijson(str(path), path.name))
    assert len(rows) == 1 and rows[0]["event_id"] == "synthetic"


@pytest.mark.parametrize("name,payload", [
    ("partial.ndjson", b'{"event_id":"ok"}\n{broken-json\n'),
    ("scalar.ndjson", b'{"event_id":"ok"}\n42\n'),
    ("partial.json", b'[{"event_id":"ok"},'),
    ("trailing.json", b'[{"event_id":"ok"}] garbage'),
    ("columns.csv", b'user,action\nalex,login,unaccounted\n'),
    ("quote.csv", b'user,action\nalex,"unterminated\n'),
    ("encoding.ndjson", b'{"event_id":"\xff"}\n'),
    ("broken.xlsx", b'not an Excel workbook'),
])
def test_assessment_rejects_incomplete_files_before_persisting_partial_rows(tmp_path, name, payload):
    from src.core.ingest.assessment_worker import _parse_file_to_store

    class Store:
        def persist_row_batch(self, *args):
            pytest.fail("An invalid file must not become a successful partial batch")

    path = tmp_path / name
    path.write_bytes(payload)
    with pytest.raises(ValueError, match="invalid_"):
        _parse_file_to_store(str(path), name, "telemetry_evidence", 0, "assessment-invalid", Store())


def test_assessment_parser_runtime_failure_is_not_swallowed(tmp_path, monkeypatch):
    from src.core.ingest import file_parser
    from src.core.ingest.assessment_worker import _parse_file_to_store

    path = tmp_path / "valid.ndjson"
    path.write_text('{"event_id":"valid"}\n', encoding="utf-8")

    def broken_reader(*args, **kwargs):
        yield {"event_id": "valid"}
        raise RuntimeError("reader stopped unexpectedly")

    monkeypatch.setattr(file_parser, "parse_file", broken_reader)
    with pytest.raises(ValueError, match="telemetry_file_processing_failed"):
        _parse_file_to_store(str(path), path.name, "telemetry_evidence", 0, "assessment-broken-reader", object())


@pytest.mark.parametrize("provided_id", [None, "row-from-another-assessment"])
def test_ingest_evidence_id_survives_enrichment_and_rejects_imported_authority(tmp_path, provided_id):
    from src.core.ingest.assessment_worker import _parse_file_to_store
    from src.core.evidence_contract.projection_builder import evidence_id_for_row
    from src.core.evidence_contract.semantic_adapters import normalize_semantics

    captured = []

    class Store:
        def persist_row_batch(self, assessment_id, rows):
            captured.extend(json.loads(json.dumps(rows)))

    raw = {"event_id": "network-transfer", "hostname": "workstation", "row_id": "vendor-record"}
    if provided_id:
        raw["evidence_id"] = provided_id
    path = tmp_path / "transfer.ndjson"
    path.write_text(json.dumps(raw) + '\n', encoding="utf-8")
    assert _parse_file_to_store(str(path), path.name, "telemetry_evidence", 17, "assessment-custody", Store()) == 1
    row = captured[0]
    reference = row["evidence_id"]
    assert reference.startswith("row_") and reference != provided_id
    assert reference != "vendor-record"
    row.update(user_canonical="resolved-owner", triage_score=0.9, derived_risk="new-context")
    assert evidence_id_for_row("assessment-custody", 17, normalize_semantics(row)) == reference
