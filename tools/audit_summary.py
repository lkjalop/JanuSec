from __future__ import annotations

import argparse
import json
from collections import Counter


def main():
    p = argparse.ArgumentParser(description='Summarize audit JSONL events')
    p.add_argument('--path', default='audits/audit_events.jsonl', help='Path to audit JSONL file')
    args = p.parse_args()

    counts = Counter()
    try:
        with open(args.path, 'r', encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    j = json.loads(line)
                    et = j.get('event_type') or 'unknown'
                    counts[et] += 1
                except Exception:
                    continue
    except FileNotFoundError:
        print('No audit file found:', args.path)
        return

    print('Audit event counts by type:')
    for k, v in counts.most_common():
        print(f'{k}: {v}')


if __name__ == '__main__':
    main()
