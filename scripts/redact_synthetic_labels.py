"""redact_synthetic_labels.py — strip analyst-authored ground-truth fields from
synthetic datasets before running platform evaluation.

Usage:
    python scripts/redact_synthetic_labels.py <input_file> [output_file]

If output_file is omitted, writes to <input>_redacted.<ext>.
Supports .json, .ndjson, .csv, .xlsx.

Fields stripped (ground-truth labels that leak the answer to the pipeline):
    analyst_notes, review_state, mitre_technique, day_of_campaign,
    spray_session_id, threat_actor, confirmed_malicious, needs_investigation,
    reviewed_benign, script_kiddie, v1_1_incidents, campaign_window,
    detection_targets, hopgraph_pivots, consecutive_failures

Top-level metadata keys also stripped from JSON files.
"""

import csv
import json
import os
import sys

REDACT_FIELDS = {
    'analyst_notes',
    'review_state',
    'mitre_technique',
    'day_of_campaign',
    'spray_session_id',
    'threat_actor',
    'confirmed_malicious',
    'needs_investigation',
    'reviewed_benign',
    'script_kiddie',
    'v1_1_incidents',
    'campaign_window',
    'detection_targets',
    'hopgraph_pivots',
    'consecutive_failures',
}

TOP_LEVEL_META_KEYS = {
    'threat_actor', 'confirmed_malicious', 'needs_investigation',
    'reviewed_benign', 'script_kiddie', 'v1_1_incidents',
    'campaign_window', 'detection_targets', 'hopgraph_pivots',
}


def redact(obj):
    if isinstance(obj, dict):
        return {k: redact(v) for k, v in obj.items() if k not in REDACT_FIELDS}
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    return obj


def redact_json(path, out_path):
    with open(path, encoding='utf-8') as f:
        data = json.load(f)
    if isinstance(data, dict):
        for k in list(data.keys()):
            if k in TOP_LEVEL_META_KEYS:
                del data[k]
        if 'events' in data:
            data['events'] = redact(data['events'])
        elif 'rows' in data:
            data['rows'] = redact(data['rows'])
        else:
            data = redact(data)
    else:
        data = redact(data)
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    print(f'JSON  → {out_path}  ({os.path.getsize(out_path):,} bytes)')


def redact_ndjson(path, out_path):
    rows_in = rows_out = 0
    with open(path, encoding='utf-8') as fin, open(out_path, 'w', encoding='utf-8') as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            rows_in += 1
            try:
                obj = json.loads(line)
                fout.write(json.dumps(redact(obj)) + '\n')
            except json.JSONDecodeError:
                fout.write(line + '\n')
            rows_out += 1
    print(f'NDJSON → {out_path}  ({rows_out}/{rows_in} rows)')


def redact_csv(path, out_path):
    with open(path, newline='', encoding='utf-8') as fin:
        reader = csv.DictReader(fin)
        fieldnames = [f for f in (reader.fieldnames or []) if f not in REDACT_FIELDS]
        rows = []
        for row in reader:
            rows.append({k: v for k, v in row.items() if k not in REDACT_FIELDS})
    with open(out_path, 'w', newline='', encoding='utf-8') as fout:
        writer = csv.DictWriter(fout, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f'CSV   → {out_path}  ({len(rows)} rows, {len(fieldnames)} columns)')


def redact_xlsx(path, out_path):
    try:
        import openpyxl
    except ImportError:
        print('ERROR: openpyxl not installed — run: pip install openpyxl')
        sys.exit(1)
    wb = openpyxl.load_workbook(path)
    for ws in wb.worksheets:
        headers = [cell.value for cell in ws[1]]
        drop_cols = {i + 1 for i, h in enumerate(headers) if h in REDACT_FIELDS}
        if drop_cols:
            for col_idx in sorted(drop_cols, reverse=True):
                ws.delete_cols(col_idx)
            print(f'  Sheet "{ws.title}": dropped {len(drop_cols)} column(s)')
    wb.save(out_path)
    print(f'XLSX  → {out_path}')


def _out_path(path, suffix='_redacted'):
    base, ext = os.path.splitext(path)
    return base + suffix + ext


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    inp = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else _out_path(inp)
    if not os.path.exists(inp):
        print(f'ERROR: file not found: {inp}')
        sys.exit(1)

    ext = os.path.splitext(inp)[1].lower()
    if ext == '.json':
        redact_json(inp, out)
    elif ext == '.ndjson':
        redact_ndjson(inp, out)
    elif ext == '.csv':
        redact_csv(inp, out)
    elif ext == '.xlsx':
        redact_xlsx(inp, out)
    else:
        print(f'ERROR: unsupported extension {ext!r} — use .json, .ndjson, .csv, .xlsx')
        sys.exit(1)


if __name__ == '__main__':
    main()
