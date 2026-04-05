from src.connectors.aws.base import AWSConnectorConfig
from src.connectors.aws.s3_access import S3AccessConnector

def test_s3_access_connector_init():
    cfg = AWSConnectorConfig(region="us-east-1")
    c = S3AccessConnector(cfg)
    assert c.name == 's3_access'
    assert c.cfg is cfg
