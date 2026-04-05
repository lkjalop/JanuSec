#!/usr/bin/env python3
"""Fetch tabular rows for a session and call /api/v1/csv/analyze_row for each row.
Writes results to dump/session_<session>_analyze.jsonl
"""
import json
import urllib.request
import urllib.parse

API_BASE = "http://127.0.0.1:8080"
SESSION = "c00e39e2c5854ee9997233a5bb1ef039"
PAGE_SIZE = 100


def get_rows(session):
    """Fetch all rows for a tabular session using offset/limit pagination.

    Returns a list of dicts mapped by header name.
    """
    offset = 0
    all_rows = []
    headers = []
    while True:
        url = f"{API_BASE}/api/v1/upload/tabular/page?session={urllib.parse.quote(session)}&offset={offset}&limit={PAGE_SIZE}"
        with urllib.request.urlopen(url, timeout=30) as resp:
            body = resp.read().decode('utf-8')
            data = json.loads(body)
            if not headers:
                headers = data.get('headers') or []
            rows = data.get('rows') or []
            for r in rows:
                obj = {headers[i]: r[i] if i < len(r) else None for i in range(len(headers))}
                all_rows.append(obj)
            next_offset = data.get('next_offset')
            if next_offset is None:
                break
            # protect against infinite loops
            if next_offset <= offset:
                break
            offset = int(next_offset)
    return all_rows


def analyze_row(row):
    url = f"{API_BASE}/api/v1/csv/analyze_row"
    payload = { 'row': row, 'options': {'threshold': 0.5} }
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode('utf-8')
        return json.loads(body)


def main():
    rows = get_rows(SESSION)
    outpath = f"dump/session_{SESSION}_analyze.jsonl"
    results = []
    with open(outpath, 'w', encoding='utf-8') as f:
        for i, r in enumerate(rows):
            print(f"Analyzing row {i+1}/{len(rows)}: host={r.get('host')} process={r.get('process_name')}")
            try:
                res = analyze_row(r)
                res['_row_index'] = i
                f.write(json.dumps(res) + '\n')
                results.append(res)
            except Exception as e:
                print(f"Failed to analyze row {i}: {e}")
    # Summary
    print('\nSummary:')
    for res in results:
        print(f"event_id={res.get('event_id')} final_decision={res.get('final_decision')} risk_score={res.get('risk_score')}")
    print(f"Wrote {len(results)} analyze results to {outpath}")

if __name__ == '__main__':
    main()
