#!/usr/bin/env python3
"""Read a CSV file from dump/ and call /api/v1/csv/analyze_row for each row.
Saves results to dump/session_manual_analyze.jsonl
"""
import csv
import json
import urllib.request
import urllib.error
from pathlib import Path

API = "http://127.0.0.1:8080/api/v1/csv/analyze_row"
CSV_PATH = Path("dump/Cyberstash_csv2_sample.csv")
OUT_PATH = Path(f"dump/session_manual_analyze.jsonl")

if not CSV_PATH.exists():
    print(f"CSV not found: {CSV_PATH}")
    raise SystemExit(2)

with CSV_PATH.open(encoding='utf-8', newline='') as fh:
    rdr = csv.reader(fh)
    header = next(rdr, None)
    rows = list(rdr)

results = []
with OUT_PATH.open('w', encoding='utf-8') as out:
    for i, r in enumerate(rows):
        row_obj = {header[j]: (r[j] if j < len(r) else '') for j in range(len(header))}
        payload = {'row': row_obj, 'options': {'threshold': 0.5}}
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(API, data=data, headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read().decode('utf-8')
                parsed = json.loads(body)
                parsed['_row_index'] = i
                out.write(json.dumps(parsed) + '\n')
                results.append(parsed)
                print(f"[{i+1}/{len(rows)}] analyzed event_id={parsed.get('event_id')} decision={parsed.get('final_decision')} score={parsed.get('risk_score')}")
        except urllib.error.HTTPError as e:
            print(f"HTTPError for row {i}: {e.code} {e.reason}")
            try:
                print(e.read().decode('utf-8'))
            except Exception:
                pass
        except Exception as e:
            print(f"Error for row {i}: {e}")

print(f"Wrote {len(results)} analyze results to {OUT_PATH}")
