"""Tests for connector production-readiness fixes.

Covers:
1. AWS SQS/Kinesis — check_ready() returns (False, reason) when boto3 missing
2. Azure Entra/Defender/Sentinel — check_ready() returns (False, reason) when msal missing
3. Sentinel workspace — raises RuntimeError on auth failure (no silent NO_TOKEN)
4. Entra/Defender — __init__ logs warning when creds configured but msal missing
5. /api/v1/status/connectors — includes dependency_status with per-connector checks
"""
from __future__ import annotations

import importlib
import sys
import unittest.mock as mock

import pytest


# ---------------------------------------------------------------------------
# Helpers — temporarily hide optional packages from the import machinery
# ---------------------------------------------------------------------------

class _HideModule:
    """Context manager that makes an import raise ImportError inside the block."""

    def __init__(self, *module_names: str) -> None:
        self._names = module_names
        self._saved: dict = {}

    def __enter__(self):
        for name in self._names:
            self._saved[name] = sys.modules.get(name, _HideModule._MISSING)
            sys.modules[name] = None  # type: ignore[assignment]
        return self

    def __exit__(self, *_):
        for name in self._names:
            saved = self._saved[name]
            if saved is _HideModule._MISSING:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = saved

    class _MISSING:
        pass


# ---------------------------------------------------------------------------
# AWS SQS: check_ready()
# ---------------------------------------------------------------------------

def test_sqs_check_ready_boto3_missing():
    """check_ready returns (False, ...) when boto3 is not available."""
    import src.connectors.aws.sqs_consumer as sqs_mod
    original = sqs_mod._BOTO3_AVAILABLE
    try:
        sqs_mod._BOTO3_AVAILABLE = False
        ok, msg = sqs_mod.SQSPoller.check_ready()
        assert not ok
        assert 'boto3' in msg.lower()
    finally:
        sqs_mod._BOTO3_AVAILABLE = original


def test_sqs_check_ready_no_queue_url(monkeypatch):
    """check_ready returns (False, ...) when SQS_QUEUE_URL is not set."""
    import src.connectors.aws.sqs_consumer as sqs_mod
    original_avail = sqs_mod._BOTO3_AVAILABLE
    original_url = sqs_mod._SQS_QUEUE_URL
    try:
        sqs_mod._BOTO3_AVAILABLE = True
        sqs_mod._SQS_QUEUE_URL = ''
        ok, msg = sqs_mod.SQSPoller.check_ready()
        assert not ok
        assert 'SQS_QUEUE_URL' in msg
    finally:
        sqs_mod._BOTO3_AVAILABLE = original_avail
        sqs_mod._SQS_QUEUE_URL = original_url


def test_sqs_check_ready_ok(monkeypatch):
    """check_ready returns (True, 'ok') when boto3 present and URL set."""
    import src.connectors.aws.sqs_consumer as sqs_mod
    original_avail = sqs_mod._BOTO3_AVAILABLE
    original_url = sqs_mod._SQS_QUEUE_URL
    try:
        sqs_mod._BOTO3_AVAILABLE = True
        sqs_mod._SQS_QUEUE_URL = 'https://sqs.us-east-1.amazonaws.com/123/test-queue'
        ok, msg = sqs_mod.SQSPoller.check_ready()
        assert ok
        assert msg == 'ok'
    finally:
        sqs_mod._BOTO3_AVAILABLE = original_avail
        sqs_mod._SQS_QUEUE_URL = original_url


# ---------------------------------------------------------------------------
# AWS Kinesis: check_ready()
# ---------------------------------------------------------------------------

def test_kinesis_check_ready_boto3_missing():
    import src.connectors.aws.kinesis_consumer as kin_mod
    original = kin_mod._BOTO3_AVAILABLE
    try:
        kin_mod._BOTO3_AVAILABLE = False
        ok, msg = kin_mod.KinesisShardConsumer.check_ready()
        assert not ok
        assert 'boto3' in msg.lower()
    finally:
        kin_mod._BOTO3_AVAILABLE = original


def test_kinesis_check_ready_no_stream(monkeypatch):
    import src.connectors.aws.kinesis_consumer as kin_mod
    original_avail = kin_mod._BOTO3_AVAILABLE
    original_stream = kin_mod._STREAM_NAME
    try:
        kin_mod._BOTO3_AVAILABLE = True
        kin_mod._STREAM_NAME = ''
        ok, msg = kin_mod.KinesisShardConsumer.check_ready()
        assert not ok
        assert 'KINESIS_STREAM_NAME' in msg
    finally:
        kin_mod._BOTO3_AVAILABLE = original_avail
        kin_mod._STREAM_NAME = original_stream


# ---------------------------------------------------------------------------
# SQS start() raises ImportError when boto3 missing but URL configured
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_sqs_start_raises_when_boto3_missing_and_url_set():
    import src.connectors.aws.sqs_consumer as sqs_mod
    original = sqs_mod._BOTO3_AVAILABLE
    try:
        sqs_mod._BOTO3_AVAILABLE = False
        poller = sqs_mod.SQSPoller(queue_url='https://sqs.us-east-1.amazonaws.com/123/q')
        with pytest.raises(ImportError, match='boto3'):
            await poller.start()
    finally:
        sqs_mod._BOTO3_AVAILABLE = original


# ---------------------------------------------------------------------------
# Azure EntraID: check_ready()
# ---------------------------------------------------------------------------

def test_entra_check_ready_msal_missing():
    import src.connectors.azure.entra_id as entra_mod
    original = entra_mod._MSAL_AVAILABLE
    try:
        entra_mod._MSAL_AVAILABLE = False
        ok, msg = entra_mod.EntraIDConnector.check_ready()
        assert not ok
        assert 'msal' in msg.lower()
    finally:
        entra_mod._MSAL_AVAILABLE = original


def test_entra_check_ready_missing_creds(monkeypatch):
    from src.connectors.azure.base import AzureConnectorConfig
    import src.connectors.azure.entra_id as entra_mod
    # Clear env vars so AzureConnectorConfig has no fallback creds
    for k in ('AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_TENANT_ID'):
        monkeypatch.delenv(k, raising=False)
    original = entra_mod._MSAL_AVAILABLE
    try:
        entra_mod._MSAL_AVAILABLE = True
        cfg = AzureConnectorConfig()
        ok, msg = entra_mod.EntraIDConnector.check_ready(cfg)
        assert not ok
    finally:
        entra_mod._MSAL_AVAILABLE = original


def test_entra_check_ready_ok(monkeypatch):
    from src.connectors.azure.base import AzureConnectorConfig
    import src.connectors.azure.entra_id as entra_mod
    monkeypatch.setenv('AZURE_CLIENT_ID', 'cid')
    monkeypatch.setenv('AZURE_CLIENT_SECRET', 'sec')
    monkeypatch.setenv('AZURE_TENANT_ID', 'tid')
    original = entra_mod._MSAL_AVAILABLE
    try:
        entra_mod._MSAL_AVAILABLE = True
        cfg = AzureConnectorConfig()
        ok, msg = entra_mod.EntraIDConnector.check_ready(cfg)
        assert ok
        assert msg == 'ok'
    finally:
        entra_mod._MSAL_AVAILABLE = original


# ---------------------------------------------------------------------------
# Azure EntraID: __init__ warns when msal missing but creds configured
# ---------------------------------------------------------------------------

def test_entra_init_warns_when_msal_missing_and_creds_set(caplog):
    from src.connectors.azure.base import AzureConnectorConfig
    import src.connectors.azure.entra_id as entra_mod
    import logging
    original = entra_mod._MSAL_AVAILABLE
    try:
        entra_mod._MSAL_AVAILABLE = False
        cfg = AzureConnectorConfig(client_id='cid', client_secret='sec', tenant_id='tid')
        with caplog.at_level(logging.WARNING, logger='src.connectors.azure.entra_id'):
            entra_mod.EntraIDConnector(cfg)
        assert any('msal' in r.message.lower() for r in caplog.records)
    finally:
        entra_mod._MSAL_AVAILABLE = original


def test_entra_init_no_warn_when_no_creds(caplog):
    from src.connectors.azure.base import AzureConnectorConfig
    import src.connectors.azure.entra_id as entra_mod
    import logging
    original = entra_mod._MSAL_AVAILABLE
    try:
        entra_mod._MSAL_AVAILABLE = False
        cfg = AzureConnectorConfig()  # no creds
        with caplog.at_level(logging.WARNING, logger='src.connectors.azure.entra_id'):
            entra_mod.EntraIDConnector(cfg)
        assert not any('msal' in r.message.lower() for r in caplog.records)
    finally:
        entra_mod._MSAL_AVAILABLE = original


# ---------------------------------------------------------------------------
# Azure DefenderCloud: check_ready() and __init__ warning
# ---------------------------------------------------------------------------

def test_defender_check_ready_msal_missing():
    import src.connectors.azure.defender_cloud as def_mod
    original = def_mod._MSAL_AVAILABLE
    try:
        def_mod._MSAL_AVAILABLE = False
        ok, msg = def_mod.DefenderCloudConnector.check_ready()
        assert not ok
        assert 'msal' in msg.lower()
    finally:
        def_mod._MSAL_AVAILABLE = original


def test_defender_init_warns_when_msal_missing_and_creds_set(caplog):
    from src.connectors.azure.base import AzureConnectorConfig
    import src.connectors.azure.defender_cloud as def_mod
    import logging
    original = def_mod._MSAL_AVAILABLE
    try:
        def_mod._MSAL_AVAILABLE = False
        cfg = AzureConnectorConfig(client_id='cid', client_secret='sec', tenant_id='tid')
        with caplog.at_level(logging.WARNING, logger='src.connectors.azure.defender_cloud'):
            def_mod.DefenderCloudConnector(cfg)
        assert any('msal' in r.message.lower() for r in caplog.records)
    finally:
        def_mod._MSAL_AVAILABLE = original


# ---------------------------------------------------------------------------
# Azure Sentinel: check_ready() and NO_TOKEN raises RuntimeError
# ---------------------------------------------------------------------------

def test_sentinel_check_ready_msal_missing():
    import src.connectors.azure.sentinel_workspace as sent_mod
    original = sent_mod._MSAL_AVAILABLE
    try:
        sent_mod._MSAL_AVAILABLE = False
        ok, msg = sent_mod.SentinelWorkspaceConnector.check_ready()
        assert not ok
        assert 'msal' in msg.lower()
    finally:
        sent_mod._MSAL_AVAILABLE = original


def test_sentinel_check_ready_missing_config():
    import src.connectors.azure.sentinel_workspace as sent_mod
    import os
    original = sent_mod._MSAL_AVAILABLE
    # Ensure env vars are empty for this test
    saved = {k: os.environ.pop(k, None) for k in
             ('AZURE_TENANT_ID', 'AZURE_SUBSCRIPTION_ID', 'SENTINEL_RESOURCE_GROUP', 'SENTINEL_WORKSPACE_NAME')}
    try:
        sent_mod._MSAL_AVAILABLE = True
        cfg = sent_mod.SentinelWorkspaceConfig(
            tenant_id='', subscription_id='', resource_group='', workspace_name=''
        )
        ok, msg = sent_mod.SentinelWorkspaceConnector.check_ready(cfg)
        assert not ok
        assert 'required' in msg.lower()
    finally:
        sent_mod._MSAL_AVAILABLE = original
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v


def test_sentinel_token_failure_raises_not_returns_no_token():
    """Auth failure must raise RuntimeError, not silently return 'NO_TOKEN'."""
    import src.connectors.azure.sentinel_workspace as sent_mod
    original = sent_mod._MSAL_AVAILABLE
    try:
        sent_mod._MSAL_AVAILABLE = False  # forces fallback HTTP path
        cfg = sent_mod.SentinelWorkspaceConfig(
            tenant_id='bad-tenant',
            client_id='bad-cid',
            client_secret='bad-sec',
            subscription_id='sub',
            resource_group='rg',
            workspace_name='ws',
        )
        provider = sent_mod._TokenProvider(cfg)
        with pytest.raises(RuntimeError, match='Sentinel token acquisition failed'):
            provider.get('https://management.azure.com/.default')
    finally:
        sent_mod._MSAL_AVAILABLE = original


# ---------------------------------------------------------------------------
# /api/v1/status/connectors includes dependency_status
# ---------------------------------------------------------------------------

def test_status_connectors_includes_dep_status():
    """The connectors status endpoint must include a dependency_status block."""
    import os
    os.environ.setdefault('PLATFORM_LITE_INIT', '1')
    os.environ.setdefault('DISABLE_DB', '1')
    from fastapi.testclient import TestClient
    from src.api.app import app

    with TestClient(app) as client:
        resp = client.get(
            '/api/v1/status/connectors',
            headers={'x-api-key': os.environ.get('API_KEY', 'devkey123')},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert 'dependency_status' in body
    deps = body['dependency_status']
    # Core entries always present
    assert 'redis' in deps
    assert 'runtime_state' in deps
    # At least one connector dep entry must exist
    connector_keys = [k for k in deps if k not in ('redis', 'runtime_state')]
    assert len(connector_keys) > 0, f'No connector dep entries found: {list(deps.keys())}'


def test_dep_status_entries_have_ready_and_detail():
    """Every connector dep entry must have 'ready' (bool) and 'detail' (str)."""
    from src.api.status_connectors import _build_dep_status
    deps = _build_dep_status()
    for key, val in deps.items():
        assert isinstance(val, dict), f'{key}: expected dict, got {type(val)}'
        assert 'ready' in val, f'{key}: missing "ready" key'
        assert 'detail' in val, f'{key}: missing "detail" key'
        assert isinstance(val['ready'], bool), f'{key}: "ready" must be bool'
