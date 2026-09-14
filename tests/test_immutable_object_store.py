from __future__ import annotations

from src.core.evidence_contract import LocalImmutableObjectStore


def test_immutable_object_store_is_content_addressed_and_idempotent(tmp_path) -> None:
    source = tmp_path / "input.jsonl"
    source.write_bytes(b'{"event":"login"}\n')
    store = LocalImmutableObjectStore(tmp_path / "objects")

    first = store.put_file(source)
    second = store.put_file(source)

    assert first == second
    assert first.locator == f"sha256://{first.sha256}"
    object_path = tmp_path / "objects" / "sha256" / first.sha256[:2] / first.sha256[2:4] / first.sha256
    assert object_path.read_bytes() == source.read_bytes()
