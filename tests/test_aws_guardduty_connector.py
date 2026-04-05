import os
import pytest
from src.connectors.aws.base import AWSConnectorConfig
from src.connectors.aws.guardduty import GuardDutyConnector

def test_guardduty_connector_init():
    cfg = AWSConnectorConfig(region="us-east-1")
    c = GuardDutyConnector(cfg)
    assert c.name == 'guardduty'
    assert c.cfg is cfg

@pytest.mark.skipif(
    os.getenv("RUN_AWS_INTEGRATION", "0") not in ("1", "true", "yes"),
    reason="Set RUN_AWS_INTEGRATION=1 to run AWS integration fetch tests",
)
def test_guardduty_fetch_findings():
    cfg = AWSConnectorConfig(region="us-east-1")
    c = GuardDutyConnector(cfg)
    list(c.fetch_findings())
