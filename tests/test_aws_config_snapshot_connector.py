from src.connectors.aws.base import AWSConnectorConfig
from src.connectors.aws.config_snapshot import ConfigSnapshotConnector

def test_config_snapshot_connector_init():
    cfg = AWSConnectorConfig(region="us-east-1")
    c = ConfigSnapshotConnector(cfg)
    assert c.name == 'config_snapshot'
    assert c.cfg is cfg
