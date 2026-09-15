from src.connectors.aws.base import AWSConnectorConfig
from src.connectors.aws.vpcflow import VPCFlowConnector

def test_vpcflow_connector_init():
    cfg = AWSConnectorConfig(region="us-east-1")
    c = VPCFlowConnector(cfg)
    assert c.name == 'vpcflow'
    assert c.cfg is cfg
