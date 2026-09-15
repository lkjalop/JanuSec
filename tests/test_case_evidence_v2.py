from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.api.models.case_evidence import CaseEvidenceViewModelV2
from src.core.model_provider_registry import discover_providers
from src.core.model_run_store import ModelRunStore, run_case_model
from src.reporting.grc_action_pack import render_grc_action_pack


def test_static_v2_fixture_validates_and_renders_five_pages() -> None:
    payload = json.loads(Path("tests/fixtures/case_evidence/v2.json").read_text(encoding="utf-8"))
    model = CaseEvidenceViewModelV2.model_validate(payload)
    rendered = render_grc_action_pack(model.model_dump(mode="json"))
    assert rendered.count('class="page"') == 5
    assert "Telemetry may identify a possible weakness" in rendered
    assert "Customer identity" in rendered
    assert "Confirmed versus suspected impact" in rendered
    assert "Entry, persistence and blast radius" in rendered
    assert "What happens next, who owns it, and what proves closure" in rendered
    assert "Provider-native revocation receipt" in rendered


def test_grc_pack_renders_human_governance_fields() -> None:
    payload = json.loads(Path("tests/fixtures/case_evidence/v2.json").read_text(encoding="utf-8"))
    payload["corrective_actions"] = [{
        "priority": "P1", "action": "Rotate exposed credentials", "owner": "IAM owner",
        "due_at": "2026-08-22", "status": "assigned", "root_cause": "Excessive standing access",
        "correction": "Credential revoked", "compensating_control": "Conditional access block",
        "analyst_signoff": "analyst@example.com", "verification": "Signed IAM snapshot",
    }]
    rendered = render_grc_action_pack(CaseEvidenceViewModelV2.model_validate(payload).model_dump(mode="json"))
    for expected in (
        "Excessive standing access", "Credential revoked", "Conditional access block",
        "analyst@example.com", "2026-08-22", "Signed IAM snapshot",
    ):
        assert expected in rendered


def test_provider_registry_always_has_deterministic_provider() -> None:
    providers = discover_providers()
    deterministic = next(item for item in providers if item["provider"] == "deterministic")
    assert deterministic["available"] is True
    assert deterministic["external_data_transfer"] is False


def test_model_runs_are_immutable_and_case_scoped(tmp_path: Path) -> None:
    store = ModelRunStore(tmp_path)
    created = store.create("tenant-a", "case-a", {"run_id": "run-fixed", "provider": "ollama", "model": "qwen"})
    assert created["immutable"] is True
    assert store.list("tenant-a", "case-a")[0]["record_hash"] == created["record_hash"]
    assert store.list("tenant-a", "case-b") == []
    with pytest.raises(FileExistsError):
        store.create("tenant-a", "case-a", {"run_id": "run-fixed", "provider": "ollama", "model": "qwen"})


def test_ollama_structured_run_disables_reasoning_only_output(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_post(url, payload, headers=None, timeout=0):
        captured.update({"url": url, "payload": payload, "timeout": timeout})
        return {"response": '{"headline":"grounded"}', "prompt_eval_count": 10, "eval_count": 5}

    monkeypatch.setattr("src.core.model_run_store._post_json", fake_post)
    text, meta = run_case_model("ollama", "qwen3.8:27b", "case")
    assert json.loads(text)["headline"] == "grounded"
    assert captured["payload"]["think"] is False
    assert captured["payload"]["options"]["num_ctx"] == 8192
    assert meta["usage"]["completion_tokens"] == 5
