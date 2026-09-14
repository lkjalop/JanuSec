from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from src.api.grc_bridge_endpoints import _grc_actor


def test_grc_actor_is_credential_identity_not_client_supplied_actor():
    auth = SimpleNamespace(subject="analyst@example.test", scopes=["grc.review"], credential_type="jwt")
    actor, role = _grc_actor(auth, {"actor": "impersonated@example.test"})
    assert actor == "analyst@example.test"
    assert role == "analyst"


def test_formal_nonconformity_requires_auditor_scope():
    with pytest.raises(HTTPException) as exc:
        _grc_actor(
            SimpleNamespace(subject="owner@example.test", scopes=["grc.write"], credential_type="jwt"),
            {"classification": "formal_nonconformity"},
        )
    assert exc.value.status_code == 403
    actor, role = _grc_actor(
        SimpleNamespace(subject="auditor@example.test", scopes=["grc.audit"], credential_type="jwt"),
        {"classification": "formal_nonconformity"},
    )
    assert actor == "auditor@example.test"
    assert role == "auditor"


def test_closure_requires_independent_verifier_scope():
    with pytest.raises(HTTPException):
        _grc_actor(
            SimpleNamespace(subject="owner@example.test", scopes=["grc.write"], credential_type="jwt"),
            {"status": "closed"},
        )


def test_api_key_cannot_become_accountable_grc_actor():
    with pytest.raises(HTTPException) as exc:
        _grc_actor(
            SimpleNamespace(
                subject="api_key:devk", scopes=["*"], credential_type="api_key",
            ),
            {"status": "approved"},
        )
    assert exc.value.status_code == 403
    assert exc.value.detail == "jwt_grc_actor_required"
