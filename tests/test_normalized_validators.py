import pytest
from src.schemas.normalized import normalize_and_validate


def test_endpoint_normalization_valid_variants():
    payload = {
        "ComputerName": "host-01",
        "Image": "C\\Windows\\System32\\notepad.exe",
        "SHA256HashData": "deadbeefcafebabe",
        "eventTime": "2025-12-20T12:00:00Z",
        "LocalIP": "10.1.1.5",
        "RemoteIP": "10.1.1.6",
    }
    norm, ok, errs = normalize_and_validate('endpoint_event', payload)
    assert ok, f"unexpected errors: {errs}"
    assert norm["host"] == "host-01"
    assert isinstance(norm.get("process"), dict)
    assert norm["process"].get("image") == "C\\Windows\\System32\\notepad.exe"
    assert norm["file_hash"] == "deadbeefcafebabe"
    assert isinstance(norm["timestamp"], (int, float)) and norm["timestamp"] > 0
    # meta should include common network context
    assert norm["meta"].get("LocalIP") == "10.1.1.5"
    assert norm["meta"].get("RemoteIP") == "10.1.1.6"


def test_identity_normalization_and_requireds():
    payload = {
        "principal": "alice@example.com",
        "hostname": "vm-123",
        "eventTime": "2025-12-21T12:34:56Z",
        "provider": "okta",
        "role": "admin",
        "action": "login"
    }
    norm, ok, errs = normalize_and_validate('identity_event', payload)
    assert ok, f"unexpected errors: {errs}"
    assert norm["user"] == "alice@example.com"
    assert norm["host"] == "vm-123"
    assert isinstance(norm["timestamp"], (int, float)) and norm["timestamp"] > 0
    assert norm["meta"].get("provider") == "okta"
    assert norm["meta"].get("role") == "admin"


def test_devops_normalization_and_requireds():
    payload = {
        "repository": "org/project",
        "event": "merge",
        "actor": "dev1",
        "eventTime": "2025-12-21T01:02:03Z",
        "branch": "main",
        "commit": "abc123"
    }
    norm, ok, errs = normalize_and_validate('devops_event', payload)
    assert ok, f"unexpected errors: {errs}"
    assert norm["repo"] == "org/project"
    assert norm["action"] == "merge"
    assert norm["user"] == "dev1"
    assert isinstance(norm["timestamp"], (int, float)) and norm["timestamp"] > 0
    assert norm["meta"].get("branch") == "main"
    assert norm["meta"].get("commit") == "abc123"


def test_invalid_identity_missing_requireds():
    payload = {"eventTime": "2025-12-21T12:00:00Z"}
    norm, ok, errs = normalize_and_validate('identity_event', payload)
    assert not ok
    assert any(e.startswith('missing:user_or_host') for e in errs)


def test_invalid_endpoint_missing_requireds():
    payload = {"eventTime": "2025-12-21T12:00:00Z"}
    norm, ok, errs = normalize_and_validate('endpoint_event', payload)
    assert not ok
    assert any(e.startswith('missing:host_or_process_or_file_hash') for e in errs)


def test_invalid_devops_missing_requireds():
    payload = {"eventTime": "2025-12-21T12:00:00Z"}
    norm, ok, errs = normalize_and_validate('devops_event', payload)
    assert not ok
    assert any(e.startswith('missing:repo_or_action_or_user') for e in errs)
