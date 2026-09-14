"""S3-backed CloudTrail connector.

Reads CloudTrail JSON files from a bucket/prefix, supports incremental
checkpointing by last-processed S3 key and/or last event timestamp. Produces
canonical envelopes suitable for ingestion.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, Iterable, Optional

from .base import AWSConnectorConfig, boto3_client, load_checkpoint, save_checkpoint, canonical_envelope, record_fetch, record_error, record_yield

logger = logging.getLogger(__name__)


class CloudTrailS3Connector:
    def __init__(self, cfg: AWSConnectorConfig, bucket: str, prefix: str | None = None):
        self.cfg = cfg
        self.bucket = bucket
        self.prefix = prefix or ''
        self.name = f'cloudtrail_s3_{bucket.replace("/","_")}'
        self.ck = load_checkpoint(self.name, cfg)

    def _list_objects_since(self, client, marker_key: Optional[str]) -> Iterable[Dict[str, Any]]:
        paginator = client.get_paginator('list_objects_v2')
        kwargs = {'Bucket': self.bucket, 'Prefix': self.prefix}
        for page in paginator.paginate(**kwargs):
            for obj in page.get('Contents', []) or []:
                key = obj.get('Key')
                if not key:
                    continue
                # Skip already-processed keys if present in checkpoint
                if marker_key and key <= marker_key:
                    continue
                yield obj

    def fetch_events(self) -> Iterable[Dict[str, Any]]:
        try:
            record_fetch(self.name)
            client = boto3_client('s3', self.cfg)
        except Exception as e:
            record_error(self.name)
            logger.exception('s3 client unavailable')
            return
        last_key = self.ck.get('last_key')
        last_ts = self.ck.get('last_ts')
        for obj in self._list_objects_since(client, last_key):
            key = obj.get('Key')
            try:
                resp = client.get_object(Bucket=self.bucket, Key=key)
                body = resp['Body'].read()
                try:
                    payload = json.loads(body)
                except Exception:
                    # CloudTrail may write JSON with multiple records per file
                    try:
                        text = body.decode('utf-8')
                        payload = json.loads(text)
                    except Exception:
                        logger.exception('failed to parse cloudtrail object %s', key)
                        continue
                # CloudTrail file format: {'Records':[...events...]}
                records = payload.get('Records') or []
                for rec in records:
                    evt_ts = int(rec.get('eventTime') and time.mktime(time.strptime(rec.get('eventTime')[:19], '%Y-%m-%dT%H:%M:%S')) or time.time())
                    if last_ts and evt_ts <= last_ts:
                        continue
                    env = canonical_envelope(rec, 'cloudtrail_s3', account_id=rec.get('recipientAccountId') or rec.get('accountId'))
                    record_yield(self.name, 1)
                    yield env
                # commit per-file progress
                self.ck['last_key'] = key
                if records:
                    try:
                        latest = max(int(time.mktime(time.strptime(r.get('eventTime')[:19], '%Y-%m-%dT%H:%M:%S'))) for r in records if r.get('eventTime'))
                        self.ck['last_ts'] = latest
                    except Exception:
                        self.ck['last_ts'] = int(time.time())
                save_checkpoint(self.name, self.cfg, self.ck)
            except Exception:
                record_error(self.name)
                logger.exception('failed to fetch cloudtrail object %s', key)

    def commit(self, marker: Any = None):
        # Marker can be last_key or last_ts; save whichever is relevant
        if isinstance(marker, str):
            self.ck['last_key'] = marker
        elif isinstance(marker, int):
            self.ck['last_ts'] = marker
        save_checkpoint(self.name, self.cfg, self.ck)
