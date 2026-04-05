import openpyxl
import re
from pathlib import Path

FILE = Path('dump/Cyberstash_csv2.xlsx')

if not FILE.exists():
    print('ERROR: file not found:', FILE)
    raise SystemExit(1)

wb = openpyxl.load_workbook(FILE, read_only=True)
ws = wb.active

# read header row
rows = ws.iter_rows(values_only=True)
headers = [str(c).strip() if c is not None else '' for c in next(rows)]

print('Detected headers:', headers)

# heuristics from csv_analyzer.js (simplified)

def infer_verdict(raw):
    # raw is a dict of header->value
    # look for explicit columns
    verdict_keys = ['verdict', 'decision', 'classification', 'label']
    for k in verdict_keys:
        for h in raw:
            if h.strip().lower() == k:
                v = raw[h]
                if v is None:
                    continue
                return str(v).strip()
    # look for score columns
    score_keys = ['score', 'risk', 'risk_score', 'confidence']
    for k in score_keys:
        for h in raw:
            if h.strip().lower() == k:
                try:
                    val = float(raw[h])
                except Exception:
                    continue
                if val >= 70:
                    return 'malicious'
                if val >= 40:
                    return 'suspicious'
                return 'benign'
    # keywords
    combined = ' '.join([str(raw[h]) for h in raw if raw[h] is not None])
    if re.search(r'crypto|mining|ransom|c2|command and control|malware|trojan|backdoor', combined, re.I):
        return 'malicious'
    if re.search(r'scan|scan detected|suspicious|indicator|ioc|anomaly', combined, re.I):
        return 'suspicious'
    return ''


def compute_dread(raw):
    # Extremely simplified: count presence of keywords mapped to factors
    factors = {
        'damage': ['ransom', 'data leak', 'exfil', 'destruct'],
        'repro': ['exploit', 'poC', 'vuln'],
        'exploit': ['cve', 'exploit', 'vuln'],
        'affected': ['host', 'endpoint', 'ip', 'domain'],
        'discover': ['scan', 'recon', 'shodan']
    }
    score = 0
    text = ' '.join([str(v) for v in raw.values() if v is not None])
    text = text.lower()
    for i, (k, kwlist) in enumerate(factors.items(), start=1):
        for kw in kwlist:
            if kw in text:
                score += i
                break
    return score


# iterate and print first 10
sample = []
for i, row in enumerate(rows, start=1):
    if i > 1000:
        break
    rec = {headers[j]: row[j] if j < len(row) else None for j in range(len(headers))}
    rec['inferred_verdict'] = infer_verdict(rec)
    rec['_dread_score'] = compute_dread(rec)
    sample.append(rec)
    if len(sample) >= 10:
        break

for idx, r in enumerate(sample, start=1):
    print(f'--- Row {idx} ---')
    for k, v in r.items():
        print(f'{k}: {v}')

print('\nTotal rows sampled:', len(sample))
