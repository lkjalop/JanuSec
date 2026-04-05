from src.connectors.aws.base import AWSConnectorConfig
from src.connectors.aws.cloudtrail import CloudTrailConnector
from src.connectors.azure.base import AzureConnectorConfig
from src.connectors.azure.event_hub import EventHubConnector
from src.connectors.azure.normalizer import normalize_entra_signin


def test_eventhub_checkpoint_resume(tmp_path):
    cfg = AzureConnectorConfig(
        checkpoint_dir=str(tmp_path),
        tenant_id='tenant-a',
        eventhub_connection_string='Endpoint=sb://demo/',
        eventhub_name='security-events',
    )

    class DummyConsumer:
        def receive(self, limit=100, checkpoint=None):
            if checkpoint is None:
                return [
                    {'offset': '1', 'body': {'eventTime': '2026-01-01T00:00:00Z', 'subscriptionId': 'sub-a', 'resourceId': '/vm/1'}},
                    {'offset': '2', 'body': {'eventTime': '2026-01-01T00:01:00Z', 'subscriptionId': 'sub-a', 'resourceId': '/vm/2'}},
                ]
            return [
                {'offset': '3', 'body': {'eventTime': '2026-01-01T00:02:00Z', 'subscriptionId': 'sub-a', 'resourceId': '/vm/3'}},
            ]

    conn = EventHubConnector(cfg, consumer_factory=lambda: DummyConsumer())
    first = list(conn.fetch_events(limit=10))
    assert len(first) == 2
    assert conn.ck['offset'] == '2'

    conn2 = EventHubConnector(cfg, consumer_factory=lambda: DummyConsumer())
    second = list(conn2.fetch_events(limit=10))
    assert len(second) == 1
    assert conn2.ck['offset'] == '3'


def test_cloudtrail_and_entra_signin_share_correlation_keys(tmp_path, monkeypatch):
    cfg = AWSConnectorConfig(checkpoint_dir=str(tmp_path))

    class DummyPaginator:
        def paginate(self, **kwargs):
            return [{
                'Events': [{
                    'CloudTrailEvent': '{"eventTime":"2026-01-01T00:00:00Z","eventName":"ConsoleLogin","sourceIPAddress":"203.0.113.5","recipientAccountId":"123456789012","userIdentity":{"arn":"alice@example.com"}}'
                }]
            }]

    class DummyClient:
        def get_paginator(self, name):
            assert name == 'lookup_events'
            return DummyPaginator()

    monkeypatch.setattr('src.connectors.aws.cloudtrail.boto3_client', lambda *args, **kwargs: DummyClient())
    cloudtrail = list(CloudTrailConnector(cfg).fetch_events(start_time=0))
    signin = normalize_entra_signin(
        {
            'createdDateTime': '2026-01-01T00:00:10Z',
            'userPrincipalName': 'alice@example.com',
            'ipAddress': '203.0.113.5',
            'appDisplayName': 'Azure Portal',
        },
        tenant_id='tenant-a',
    )
    overlap = set(cloudtrail[0].get('correlation_keys') or []).intersection(signin.get('correlation_keys') or [])
    assert 'actor:alice@example.com' in overlap
    assert 'ip:203.0.113.5' in overlap
