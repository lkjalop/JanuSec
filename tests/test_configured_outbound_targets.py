import asyncio
import importlib
import json
from types import SimpleNamespace

import pytest
from src.security.configured_targets import configured_target, configured_webhook


@pytest.mark.parametrize("value", ["[]", "{}", "null", "invalid", '[42]'])
def test_unconfigured_targets_fail_closed(monkeypatch, value):
    monkeypatch.setenv("JANUSEC_APPROVED_WEBHOOK_URLS", value)
    with pytest.raises(ValueError):
        configured_webhook("https://example.com/hook")


def test_exact_destination_match_required(monkeypatch):
    monkeypatch.setenv("TARGETS", json.dumps(["https://example.com/hook"]))
    for target in ("https://example.com/hook/extra", "https://example.com.attacker.test/hook", "http://127.0.0.1"):
        with pytest.raises(ValueError):
            configured_target(target, "TARGETS")
    assert configured_target("https://example.com/hook", "TARGETS") == "https://example.com/hook"


def test_even_configured_private_webhook_is_denied(monkeypatch):
    monkeypatch.setenv("JANUSEC_APPROVED_WEBHOOK_URLS", '["https://127.0.0.1/hook"]')
    with pytest.raises(ValueError):
        configured_webhook("https://127.0.0.1/hook")


@pytest.mark.parametrize("scanner", ["trivy", "syft", "grype"])
def test_real_scanner_rejects_unapproved_targets_before_process(monkeypatch, scanner):
    monkeypatch.setenv("SCANNERS_REAL_MODE", "1")
    monkeypatch.delenv("JANUSEC_APPROVED_SCANNER_TARGETS", raising=False)
    monkeypatch.setattr("subprocess.run", lambda *a, **k: pytest.fail("process started"))
    cls = getattr(importlib.import_module(f"src.collectors.scanners.{scanner}_connector"), scanner.title() + "Connector")
    for target in ("--config=evil", "dir:/", "alpine:latest"):
        with pytest.raises(ValueError):
            asyncio.run(cls().run_scan(target))


@pytest.mark.parametrize("scanner", ["trivy", "syft", "grype"])
@pytest.mark.parametrize("exit_code", [0, 1])
def test_real_scans_do_not_invent_demo_findings(monkeypatch, scanner, exit_code):
    monkeypatch.setenv("SCANNERS_REAL_MODE", "1")
    monkeypatch.setenv("JANUSEC_APPROVED_SCANNER_TARGETS", '["alpine:3.20"]')
    def run(command, **kwargs):
        assert command[-2:] == ["--", "alpine:3.20"]
        return SimpleNamespace(returncode=exit_code, stdout="{}")
    monkeypatch.setattr("subprocess.run", run)
    cls = getattr(importlib.import_module(f"src.collectors.scanners.{scanner}_connector"), scanner.title() + "Connector")
    if exit_code:
        with pytest.raises(RuntimeError, match="no findings produced"):
            asyncio.run(cls().run_scan("alpine:3.20"))
    else:
        assert asyncio.run(cls().run_scan("alpine:3.20"))["components"] == []


def test_unapproved_notification_does_not_call_connector(monkeypatch):
    from src.soar.runner import PlaybookRunner
    monkeypatch.delenv("JANUSEC_APPROVED_WEBHOOK_URLS", raising=False)
    monkeypatch.setattr("src.soar.runner.get_registry", lambda: pytest.fail("connector invoked"))
    result = asyncio.run(PlaybookRunner(dry_run=False)._step_notify({"webhook_url": "http://127.0.0.1"}))
    assert result.ok is False


def test_auth_debug_does_not_log_supplied_api_key(monkeypatch, caplog):
    import logging
    from fastapi import HTTPException
    from src.security import auth
    supplied = 'dummy-regression-credential'
    monkeypatch.setenv('AUTH_DEBUG', '1')
    monkeypatch.setattr(auth, '_load_api_keys', lambda: {})
    with caplog.at_level(logging.DEBUG, logger='src.security.auth'):
        with pytest.raises(HTTPException):
            asyncio.run(auth.auth_dependency(x_api_key=supplied, authorization=None, required_scopes=[]))
    assert supplied not in caplog.text
    assert 'api_key_present' in caplog.text
