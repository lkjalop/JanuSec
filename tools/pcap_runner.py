"""Small runner to parse a PCAP file and print extracted flow events.

Usage:
    python tools/pcap_runner.py path/to/file.pcap

This is intentionally minimal and useful for manual testing and demos.
"""
from __future__ import annotations
import sys, json
from ingestion.pcap_ingestor import PCAPIngestor


def main():
    if len(sys.argv) < 2:
        print('Usage: pcap_runner.py <pcap-file>')
        return
    path = sys.argv[1]
    with open(path, 'rb') as f:
        data = f.read()
    ing = PCAPIngestor()
    events = list(ing.parse(data))
    print(json.dumps({'extracted': len(events), 'sample': events[:3]}, indent=2))


if __name__ == '__main__':
    main()
