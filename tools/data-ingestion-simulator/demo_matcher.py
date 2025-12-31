#!/usr/bin/env python3
"""Simple demo that reads synthetic events from stdin and applies sanitized rule templates.

This is only for demonstration and does not contain any production detection logic.
"""
import sys
import json


def match_kape(event):
    return event.get('process') in ('kape.exe','gkape.exe') and event.get('host','').startswith('host-')


def main():
    for line in sys.stdin:
        ev = json.loads(line)
        if match_kape(ev):
            print(json.dumps({'event_id': ev.get('event_id'), 'alert': 'kape_execution_suspicious'}))


if __name__ == '__main__':
    main()
