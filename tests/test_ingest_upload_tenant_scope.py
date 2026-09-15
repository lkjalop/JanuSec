from __future__ import annotations

import datetime
from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.api.ingest_endpoints import router
from src.core.ingest import assessment_worker, store
from src.security.auth import AuthContext


def _client(*, auth_tenant: str | None, state_tenant: str | None) -> TestClient:
    app = FastAPI()

    @app.middleware("http")
    async def _scope_request(request: Request, call_next):
        request.state.auth = AuthContext("test", ["*"], tenant_id=auth_tenant)
        if state_tenant is not None:
            request.state.tenant_id = state_tenant
        return await call_next(request)

    app.include_router(router)
    return TestClient(app)


def _stub_ingest(monkeypatch, tmp_path: Path) -> dict:
    captured: dict = {}

    def _raw_dir_for(assessment_id: str, tenant_id: str | None = None) -> str:
        captured["raw_tenant"] = tenant_id
        path = tmp_path / "raw" / str(tenant_id or "legacy") / assessment_id
        path.mkdir(parents=True, exist_ok=True)
        return str(path)

    monkeypatch.setattr(store, "raw_dir_for", _raw_dir_for)
    monkeypatch.setattr(
        store,
        "create_job",
        lambda assessment_id, org="unknown": captured.update(
            assessment_id=assessment_id, created_org=org
        ),
    )
    monkeypatch.setattr(store, "register_file", lambda *args, **kwargs: None)
    monkeypatch.setattr(store, "update_job", lambda *args, **kwargs: None)
    monkeypatch.setattr(assessment_worker, "start_worker", lambda: None)
    monkeypatch.setattr(
        assessment_worker,
        "enqueue_job",
        lambda assessment_id, org, saved: captured.update(
            enqueued_org=org, saved=saved
        ),
    )
    return captured


def _upload(client: TestClient, *, org: str | None, headers: dict | None = None):
    data = {} if org is None else {"org": org}
    return client.post(
        "/api/v1/assessments/upload",
        data=data,
        files={"files": ("events.csv", b"user,host\nalice,host-1\n", "text/csv")},
        headers=headers or {},
    )


def test_scoped_auth_rejects_form_tenant_override(monkeypatch, tmp_path):
    captured = _stub_ingest(monkeypatch, tmp_path)
    response = _upload(
        _client(auth_tenant="tenant-a", state_tenant="tenant-a"),
        org="tenant-b",
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "tenant_scope_mismatch"
    assert captured == {}


def test_scoped_auth_tenant_is_used_for_job_and_queue(monkeypatch, tmp_path):
    captured = _stub_ingest(monkeypatch, tmp_path)
    response = _upload(
        _client(auth_tenant="tenant-a", state_tenant="default"),
        org="tenant-a",
    )

    assert response.status_code == 202, response.text
    assert captured["created_org"] == "tenant-a"
    assert captured["enqueued_org"] == "tenant-a"
    assert captured["raw_tenant"] == "tenant-a"


def test_upload_rejects_failed_raw_registration(monkeypatch, tmp_path):
    captured = _stub_ingest(monkeypatch, tmp_path)
    def fail(*args, **kwargs):
        raise OSError('synthetic database failure')
    monkeypatch.setattr(store, 'register_file', fail)
    response = _upload(_client(auth_tenant='tenant-a', state_tenant='tenant-a'), org='tenant-a')
    assert response.status_code == 503
    assert response.json()['detail'] == 'Raw capture registration failed'
    assert 'enqueued_org' not in captured


def test_upload_byte_limit_prevents_enqueue(monkeypatch, tmp_path):
    from src.api import ingest_endpoints
    captured = _stub_ingest(monkeypatch, tmp_path)
    monkeypatch.setattr(ingest_endpoints, '_MAX_UPLOAD_BYTES', 8)
    response = _upload(_client(auth_tenant='tenant-a', state_tenant='tenant-a'), org='tenant-a')
    assert response.status_code == 413
    assert 'enqueued_org' not in captured


def test_explicit_request_tenant_rejects_form_override(monkeypatch, tmp_path):
    captured = _stub_ingest(monkeypatch, tmp_path)
    response = _upload(
        _client(auth_tenant=None, state_tenant="tenant-a"),
        org="tenant-b",
        headers={"X-Tenant-ID": "tenant-a"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "tenant_scope_mismatch"
    assert captured == {}


def test_dev_test_legacy_org_can_replace_implicit_default(monkeypatch, tmp_path):
    captured = _stub_ingest(monkeypatch, tmp_path)
    monkeypatch.setenv("TEST_HELPERS_ENABLED", "1")
    monkeypatch.setenv("ALLOW_TENANT_OVERRIDE", "1")
    monkeypatch.setenv("APP_ENV", "test")
    response = _upload(
        _client(auth_tenant=None, state_tenant="default"),
        org="demo-tenant",
    )

    assert response.status_code == 202, response.text
    assert captured["created_org"] == "demo-tenant"
    assert captured["enqueued_org"] == "demo-tenant"


def test_dev_mode_does_not_implicitly_allow_form_tenant_override(
    monkeypatch, tmp_path
):
    captured = _stub_ingest(monkeypatch, tmp_path)
    monkeypatch.setenv("TEST_HELPERS_ENABLED", "1")
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.delenv("ALLOW_TENANT_OVERRIDE", raising=False)

    response = _upload(
        _client(auth_tenant=None, state_tenant="default"),
        org="demo-tenant",
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "tenant_scope_mismatch"
    assert captured == {}


def test_unsafe_form_tenant_is_rejected_before_filesystem_use(monkeypatch, tmp_path):
    captured = _stub_ingest(monkeypatch, tmp_path)
    response = _upload(
        _client(auth_tenant=None, state_tenant="default"),
        org="../outside",
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "invalid_tenant_identifier"
    assert captured == {}
    assert not (tmp_path / "raw").exists()


def test_worker_persistence_rejects_tenant_path_escape(monkeypatch, tmp_path):
    monkeypatch.setenv("SESSION_PERSIST_DIR", str(tmp_path / "assessments"))
    escaped = tmp_path / "outside"

    result = assessment_worker._persist_assessment_json(
        "assessment-123", "../outside", {"assessment_id": "assessment-123"}
    )

    assert result is None
    assert not escaped.exists()


def test_worker_persistence_uses_validated_tenant_directory(monkeypatch, tmp_path):
    root = tmp_path / "assessments"
    monkeypatch.setenv("SESSION_PERSIST_DIR", str(root))
    data = {"assessment_id": "assessment-123"}

    result = assessment_worker._persist_assessment_json(
        "assessment-123", "tenant-a", data
    )

    datepart = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    expected = root / "tenant-a" / datepart / "assessment-123.json"
    assert result == str(expected)
    assert expected.exists()
    assert expected.resolve().is_relative_to(root.resolve())


def test_worker_persistence_avoids_case_folded_tenant_alias(monkeypatch, tmp_path):
    root = tmp_path / "assessments"
    monkeypatch.setenv("SESSION_PERSIST_DIR", str(root))

    lower = assessment_worker._persist_assessment_json(
        "assessment-lower", "tenant-a", {"assessment_id": "assessment-lower"}
    )
    mixed = assessment_worker._persist_assessment_json(
        "assessment-mixed", "Tenant-A", {"assessment_id": "assessment-mixed"}
    )

    assert lower is not None and mixed is not None
    assert Path(lower).parents[1].name == "tenant-a"
    assert Path(mixed).parents[1].name.startswith("tenant-a--")
    assert Path(lower).parents[1] != Path(mixed).parents[1]


def test_raw_upload_directory_is_tenant_partitioned_and_contained(
    monkeypatch, tmp_path
):
    root = tmp_path / "raw"
    monkeypatch.setattr(store, "_RAW_ROOT", str(root))

    result = Path(store.raw_dir_for("assessment-123", tenant_id="tenant-a"))

    assert result == (root / "tenant-a" / "assessment-123").resolve()
    assert result.is_dir()
    assert result.is_relative_to(root.resolve())
    with pytest.raises(ValueError, match="invalid_tenant_id"):
        store.raw_dir_for("assessment-123", tenant_id="../outside")


def test_case_distinct_tenants_do_not_alias_on_case_folding_filesystems(
    monkeypatch, tmp_path
):
    root = tmp_path / "raw"
    monkeypatch.setattr(store, "_RAW_ROOT", str(root))

    lower = Path(store.raw_dir_for("assessment-123", tenant_id="tenant-a"))
    mixed = Path(store.raw_dir_for("assessment-123", tenant_id="Tenant-A"))

    assert lower != mixed
    assert lower.parent.name == "tenant-a"
    assert mixed.parent.name.startswith("tenant-a--")
    assert mixed.is_relative_to(root.resolve())


def test_duplicate_raw_filename_is_rejected_before_overwrite(monkeypatch, tmp_path):
    captured = _stub_ingest(monkeypatch, tmp_path)
    response = _client(
        auth_tenant="tenant-a", state_tenant="tenant-a"
    ).post(
        "/api/v1/assessments/upload",
        data={"org": "tenant-a"},
        files=[
            ("files", ("same.csv", b"user\nalice\n", "text/csv")),
            ("files", ("same.csv", b"user\nbob\n", "text/csv")),
        ],
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "Duplicate upload filename: same.csv"
    assert "enqueued_org" not in captured
