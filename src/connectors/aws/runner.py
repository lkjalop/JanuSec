"""Small CLI runner for connectors.

Example usage:
  python -m src.connectors.aws.runner cloudtrail_s3 --bucket my-logs-bucket --prefix AWSLogs/123456789/CloudTrail/

The runner prints canonical envelopes to stdout (one JSON per line).
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any

from .base import AWSConnectorConfig
from .cloudtrail_s3 import CloudTrailS3Connector

logger = logging.getLogger(__name__)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument('connector', choices=['cloudtrail_s3'])
    p.add_argument('--bucket', required=True)
    p.add_argument('--prefix', default='')
    p.add_argument('--role-arn', default=None)
    p.add_argument('--region', default=None)
    p.add_argument('--checkpoint-dir', default=None)
    args = p.parse_args(argv)

    cfg = AWSConnectorConfig(role_arn=args.role_arn, region=args.region, checkpoint_dir=args.checkpoint_dir)

    if args.connector == 'cloudtrail_s3':
        conn = CloudTrailS3Connector(cfg, bucket=args.bucket, prefix=args.prefix)
        for ev in conn.fetch_events():
            try:
                print(json.dumps(ev, default=str))
            except Exception:
                print(str(ev))
    return 0


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())
