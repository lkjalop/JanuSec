"""IAM / CloudFormation change tracker connector skeleton."""
from __future__ import annotations

import logging
from typing import Any, Dict, Iterable

from .base import AWSConnectorConfig, boto3_client, load_checkpoint, save_checkpoint, canonical_envelope, record_fetch

logger = logging.getLogger(__name__)

class IAMChangesConnector:
    def __init__(self, cfg: AWSConnectorConfig):
        self.cfg = cfg
        self.name = 'iam_changes'
        self.ck = load_checkpoint(self.name, cfg)

    def fetch_changes(self) -> Iterable[Dict[str, Any]]:
        # Use CloudTrail + Config to find IAM/CFN changes
        record_fetch(self.name)
        yield from []

    def commit(self, marker: Any):
        self.ck['marker'] = marker
        save_checkpoint(self.name, self.cfg, self.ck)
