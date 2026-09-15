from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parent / "fixtures" / "golden_breach"


def _rows(name: str) -> list[dict]:
    return [json.loads(line) for line in (ROOT / name).read_text(encoding="utf-8").splitlines()]


def test_golden_manifest_names_all_required_variants() -> None:
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    assert set(manifest["variants"]) == {"breach", "benign", "missing_sensor", "delayed_log", "cross_tenant"}


def test_delayed_log_preserves_valid_and_known_time() -> None:
    cloud = _rows("delayed_log.jsonl")[1]
    assert cloud["event_time"] == "2026-08-18T10:16:00Z"
    assert cloud["known_at"] == "2026-08-18T10:35:00Z"


def test_cross_tenant_variant_cannot_be_joined_inside_one_partition() -> None:
    rows = _rows("cross_tenant.jsonl")
    partitions = {
        tenant: [row for row in rows if row["tenant_id"] == tenant] for tenant in {row["tenant_id"] for row in rows}
    }
    assert all(len(partition) == 1 for partition in partitions.values())
