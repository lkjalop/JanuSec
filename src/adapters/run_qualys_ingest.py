"""Small runner to invoke Qualys ingestion - intended to be wired to a scheduler.

Usage examples:
    python -m src.adapters.run_qualys_ingest --client-id X --client-secret Y

This script prints JSON lines for each mapped artifact to stdout; replace with
pipeline-specific ingestion calls as needed.
"""
import argparse
import json
from src.adapters.bridge import ingest_vulns_from_connector


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client-id', required=True)
    parser.add_argument('--client-secret', required=True)
    parser.add_argument('--api-base', default='https://qualysapi.example.com')
    args = parser.parse_args()
    for art in ingest_vulns_from_connector('qualys', client_id=args.client_id, client_secret=args.client_secret, api_base=args.api_base):
        print(json.dumps(art))


if __name__ == '__main__':
    main()
