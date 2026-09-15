"""Download or ingest a local MITRE STIX file and normalize techniques.

Usage:
  python scripts/ingest_mitre.py --file path/to/enterprise-attack.json
"""
from __future__ import annotations
import argparse
import json
import logging
import os
import sys

from src.core.mitre_ingest import ingest_from_stix

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', help='Path to STIX JSON file', required=True)
    args = parser.parse_args()
    if not os.path.exists(args.file):
        logger.error('File not found: %s', args.file)
        sys.exit(2)
    with open(args.file, 'r', encoding='utf-8') as fh:
        stix = json.load(fh)
    out = ingest_from_stix(stix)
    logger.info('Ingested %d techniques', len(out))


if __name__ == '__main__':
    main()
