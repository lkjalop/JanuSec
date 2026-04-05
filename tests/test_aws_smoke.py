import os
import json
import sys
import pytest

from src.connectors.aws.base import AWSConnectorConfig, checkpoint_path, save_checkpoint, load_checkpoint, canonical_envelope, hashlib_fingerprint


def test_canonical_envelope_hash_id():
    raw = {"EventId": None, "detail": {"action": "TestAction"}}
    env = canonical_envelope(raw, source="cloudtrail")
    assert env["source"] == "cloudtrail"
    assert isinstance(env["recv_ts"], int)
    # id should be a sha256 hex string when no explicit id present
    assert isinstance(env["id"], str)
    assert len(env["id"]) == 64
    int(env["id"], 16)


def test_checkpoint_roundtrip(tmp_path):
    cfg = AWSConnectorConfig(checkpoint_dir=str(tmp_path))
    data = {"last_ts": 12345, "marker": "s3://bucket/prefix"}
    save_checkpoint("cloudtrail", cfg, data)
    loaded = load_checkpoint("cloudtrail", cfg)
    assert loaded == data
    # path exists
    p = checkpoint_path("cloudtrail", cfg)
    assert os.path.exists(p)


def test_boto3_required_guard(monkeypatch):
    # Ensure boto3 import results in failure for this test
    monkeypatch.setitem(sys.modules, 'boto3', None)
    monkeypatch.setitem(sys.modules, 'botocore.config', None)
    cfg = AWSConnectorConfig(region="us-east-1")
    from src.connectors.aws.base import boto3_client
    with pytest.raises(RuntimeError):
        boto3_client('cloudtrail', cfg)
