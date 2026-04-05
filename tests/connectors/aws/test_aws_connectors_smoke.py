from __future__ import annotations

import json


def test_aws_base_checkpoint_path(tmp_path):
    from src.connectors.aws.base import AWSConnectorConfig, checkpoint_path

    cfg = AWSConnectorConfig(checkpoint_dir=str(tmp_path))
    path = checkpoint_path("cloudtrail", cfg)
    assert path.endswith("aws_cloudtrail.checkpoint.json")


def test_cloudtrail_connector_fetch(monkeypatch, tmp_path):
    from src.connectors.aws import cloudtrail

    cfg = cloudtrail.AWSConnectorConfig(checkpoint_dir=str(tmp_path))

    class DummyPaginator:
        def paginate(self, **kwargs):
            return [{"Events": [{"EventId": "evt1", "AccountId": "123"}]}]

    class DummyClient:
        def get_paginator(self, name):
            assert name == "lookup_events"
            return DummyPaginator()

    monkeypatch.setattr(cloudtrail, "boto3_client", lambda service, cfg: DummyClient())
    conn = cloudtrail.CloudTrailConnector(cfg)
    events = list(conn.fetch_events(start_time=0))
    assert events and events[0]["source"] == "cloudtrail"


def test_cloudtrail_s3_connector_fetch(monkeypatch, tmp_path):
    from src.connectors.aws import cloudtrail_s3

    cfg = cloudtrail_s3.AWSConnectorConfig(checkpoint_dir=str(tmp_path))

    class DummyBody:
        def __init__(self, payload: bytes):
            self._payload = payload

        def read(self):
            return self._payload

    class DummyPaginator:
        def paginate(self, **kwargs):
            return [{"Contents": [{"Key": "k1"}]}]

    class DummyClient:
        def get_paginator(self, name):
            assert name == "list_objects_v2"
            return DummyPaginator()

        def get_object(self, Bucket, Key):
            payload = json.dumps(
                {"Records": [{"eventTime": "2024-01-01T00:00:00Z", "recipientAccountId": "123"}]}
            ).encode("utf-8")
            return {"Body": DummyBody(payload)}

    monkeypatch.setattr(cloudtrail_s3, "boto3_client", lambda service, cfg: DummyClient())
    conn = cloudtrail_s3.CloudTrailS3Connector(cfg, bucket="demo", prefix="")
    events = list(conn.fetch_events())
    assert events and events[0]["source"] == "cloudtrail_s3"


def test_cloudwatch_connector_smoke(tmp_path):
    from src.connectors.aws.cloudwatch import AWSConnectorConfig, CloudWatchConnector

    conn = CloudWatchConnector(AWSConnectorConfig(checkpoint_dir=str(tmp_path)))
    assert list(conn.fetch_events()) == []
    conn.commit("marker")


def test_config_snapshot_connector_smoke(tmp_path):
    from src.connectors.aws.config_snapshot import AWSConnectorConfig, ConfigSnapshotConnector

    conn = ConfigSnapshotConnector(AWSConnectorConfig(checkpoint_dir=str(tmp_path)))
    assert list(conn.fetch_config_items()) == []
    conn.commit("marker")


def test_guardduty_connector_fetch(monkeypatch, tmp_path):
    from src.connectors.aws import guardduty

    cfg = guardduty.AWSConnectorConfig(checkpoint_dir=str(tmp_path))

    class DummyPaginator:
        def paginate(self, **kwargs):
            return [{"FindingIds": ["f1"]}]

    class DummyClient:
        def list_detectors(self):
            return {"DetectorIds": ["det1"]}

        def get_paginator(self, name):
            assert name == "list_findings"
            return DummyPaginator()

        def get_findings(self, DetectorId, FindingIds):
            return {"Findings": [{"AwsAccountId": "123", "Id": FindingIds[0]}]}

    monkeypatch.setattr(guardduty, "boto3_client", lambda service, cfg: DummyClient())
    conn = guardduty.GuardDutyConnector(cfg)
    events = list(conn.fetch_findings())
    assert events and events[0]["source"] == "guardduty"


def test_iam_changes_connector_smoke(tmp_path):
    from src.connectors.aws.iam_changes import AWSConnectorConfig, IAMChangesConnector

    conn = IAMChangesConnector(AWSConnectorConfig(checkpoint_dir=str(tmp_path)))
    assert list(conn.fetch_changes()) == []
    conn.commit("marker")


def test_s3_access_connector_smoke(tmp_path):
    from src.connectors.aws.s3_access import AWSConnectorConfig, S3AccessConnector

    conn = S3AccessConnector(AWSConnectorConfig(checkpoint_dir=str(tmp_path)))
    assert list(conn.fetch_access_logs()) == []
    conn.commit("marker")


def test_securityhub_connector_fetch(monkeypatch, tmp_path):
    from src.connectors.aws import securityhub

    cfg = securityhub.AWSConnectorConfig(checkpoint_dir=str(tmp_path))

    class DummyPaginator:
        def paginate(self, **kwargs):
            return [{"Findings": [{"AwsAccountId": "123", "Id": "sh1"}]}]

    class DummyClient:
        def get_paginator(self, name):
            assert name == "get_findings"
            return DummyPaginator()

    monkeypatch.setattr(securityhub, "boto3_client", lambda service, cfg: DummyClient())
    conn = securityhub.SecurityHubConnector(cfg)
    events = list(conn.fetch_findings())
    assert events and events[0]["source"] == "securityhub"


def test_vpcflow_connector_smoke(tmp_path):
    from src.connectors.aws.vpcflow import AWSConnectorConfig, VPCFlowConnector

    conn = VPCFlowConnector(AWSConnectorConfig(checkpoint_dir=str(tmp_path)))
    assert list(conn.fetch_records()) == []
    conn.commit("marker")


def test_runner_main_smoke(monkeypatch):
    from src.connectors.aws import runner

    class DummyConnector:
        def __init__(self, cfg, bucket, prefix=""):
            self.cfg = cfg
            self.bucket = bucket
            self.prefix = prefix

        def fetch_events(self):
            return []

    monkeypatch.setattr(runner, "CloudTrailS3Connector", DummyConnector)
    rc = runner.main(["cloudtrail_s3", "--bucket", "demo-bucket"])
    assert rc == 0
