"""AWS Config snapshot / CSPM connector skeleton."""
from __future__ import annotations

import logging
from typing import Any, Dict, Iterable

from .base import AWSConnectorConfig, boto3_client, load_checkpoint, save_checkpoint, canonical_envelope, record_fetch

logger = logging.getLogger(__name__)

class ConfigSnapshotConnector:
    def __init__(self, cfg: AWSConnectorConfig):
        self.cfg = cfg
        self.name = 'config_snapshot'
        self.ck = load_checkpoint(self.name, cfg)

    def fetch_config_items(self) -> Iterable[Dict[str, Any]]:
        # In production either call config.get_resource_config_history or list_discovered_resources
        record_fetch(self.name)
        yield from []

    def commit(self, marker: Any):
        self.ck['marker'] = marker
        save_checkpoint(self.name, self.cfg, self.ck)
