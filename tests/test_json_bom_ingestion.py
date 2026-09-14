import json
import pytest
from src.core.ingest.file_parser import parse_file, _parse_json_ijson


@pytest.mark.parametrize("suffix", [".json", ".ndjson"])
@pytest.mark.parametrize("bom", [True, False])
def test_json_row_survives_utf8_bom(tmp_path, suffix, bom):
    row = {"title": "No credential dumping occurred", "status": "closed"}
    path = tmp_path / ("negative" + suffix)
    path.write_text(json.dumps(row), encoding="utf-8-sig" if bom else "utf-8")
    rows = list(parse_file(str(path), filename=path.name))
    assert len(rows) == 1 and rows[0]["title"] == row["title"]


@pytest.mark.parametrize("container", [lambda row: [row], lambda row: {"events": [row]}])
def test_streaming_json_accepts_bom(tmp_path, container):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(container({"event_id": "synthetic"})), encoding="utf-8-sig")
    rows = list(_parse_json_ijson(str(path), path.name))
    assert len(rows) == 1 and rows[0]["event_id"] == "synthetic"
