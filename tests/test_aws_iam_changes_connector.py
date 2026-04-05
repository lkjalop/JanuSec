from src.connectors.aws.base import AWSConnectorConfig
from src.connectors.aws.iam_changes import IAMChangesConnector

def test_iam_changes_connector_init():
    cfg = AWSConnectorConfig(region="us-east-1")
    c = IAMChangesConnector(cfg)
    assert c.name == 'iam_changes'
    assert c.cfg is cfg
