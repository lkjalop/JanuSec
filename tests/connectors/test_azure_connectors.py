from src.connectors.azure.base import AzureConnectorConfig
from src.connectors.azure.event_hub import EventHubConnector
from src.connectors.azure.entra_id import EntraIDConnector
from src.connectors.azure.defender_cloud import DefenderCloudConnector


def test_event_hub_connector_fetch(tmp_path):
    cfg = AzureConnectorConfig(checkpoint_dir=str(tmp_path), tenant_id='t1')

    class DummyConsumer:
        def receive(self, limit=100, checkpoint=None):
            return [{'offset': '1', 'body': {'eventType': 'Administrative', 'subscriptionId': 'sub1', 'resourceId': 'r1', 'timestamp': '2026-01-01T00:00:00Z'}}]

    conn = EventHubConnector(cfg, consumer_factory=lambda: DummyConsumer())
    events = list(conn.fetch_events())
    assert events and events[0]['source'] == 'azure_eventhub'
    assert conn.ck.get('offset') == '1'


def test_entra_connector_signins_and_audits(tmp_path):
    cfg = AzureConnectorConfig(checkpoint_dir=str(tmp_path), tenant_id='t1', subscription_id='sub1')

    def _request_json(kind, payload):
        if kind == 'signins':
            return {'value': [{'userPrincipalName': 'alice@example.com', 'ipAddress': '203.0.113.10', 'createdDateTime': '2026-01-01T00:00:00Z'}]}
        return {'value': [{'activityDisplayName': 'Add member to role', 'activityDateTime': '2026-01-02T00:00:00Z', 'initiatedBy': {'user': {'userPrincipalName': 'bob@example.com'}}}]}

    conn = EntraIDConnector(cfg, request_json=_request_json)
    signins = list(conn.fetch_signins())
    audits = list(conn.fetch_audits())
    assert signins and signins[0]['source'] == 'azure_entra_signin'
    assert audits and audits[0]['source'] == 'azure_entra_audit'


def test_defender_cloud_connector_fetch(tmp_path):
    cfg = AzureConnectorConfig(checkpoint_dir=str(tmp_path), tenant_id='t1', subscription_id='sub1')
    conn = DefenderCloudConnector(
        cfg,
        request_json=lambda payload: {
            'findings': [
                {
                    'displayName': 'Suspicious container activity',
                    'severity': 'High',
                    'resourceId': '/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1',
                    'createdDateTime': '2026-01-03T00:00:00Z',
                }
            ]
        },
    )
    findings = list(conn.fetch_findings())
    assert findings and findings[0]['source'] == 'azure_defender_cloud'
