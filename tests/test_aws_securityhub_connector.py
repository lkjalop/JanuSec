import os
import pytest
from src.connectors.aws.base import AWSConnectorConfig
from src.connectors.aws.securityhub import SecurityHubConnector

def test_securityhub_connector_init():
    cfg = AWSConnectorConfig(region="us-east-1")
    c = SecurityHubConnector(cfg)
    assert c.name == 'securityhub'
    assert c.cfg is cfg

@pytest.mark.skipif(
    os.getenv("RUN_AWS_INTEGRATION", "0") not in ("1", "true", "yes"),
    reason="Set RUN_AWS_INTEGRATION=1 to run AWS integration fetch tests",
)
def test_securityhub_fetch_findings():
    cfg = AWSConnectorConfig(region="us-east-1")
    c = SecurityHubConnector(cfg)
    list(c.fetch_findings())
