"""Heuristic remapper: map CSV columns (list rows) to canonical pipeline fields and run triage on samples.
Run from repo root (python scripts/heuristic_remap_triage.py).
"""
import json, os, re
from pprint import pprint

JOB_PATH = 'data/sessions/backfill_jobs/assessment-1764486813-78e8900e.json'
ASSESS_PATH = 'data/assessments/unknown/2025-11-30/assessment-1764486813-78e8900e.json'
SAMPLE_COUNT = 50

hex_re = re.compile(r'^[0-9a-fA-F]{40,128}$')
uuid_re = re.compile(r'^[0-9a-fA-F-]{36,36}$')

def detect_value_types(samples):
    stats = {'has_path':0,'has_exe':0,'has_hash':0,'has_uuid':0,'has_float':0,'has_int':0,'has_label':0,'has_json_like':0}
    known_labels = {'suspicious','probably good','probably_bad','verified good','unknown','suspicious','undetermined'}
    for v in samples:
        if v is None:
            continue
        s = str(v).strip()
        if not s:
            continue
        if '\\' in s or '/' in s:
            stats['has_path']+=1
        if s.lower().endswith(('.exe','.dll','.sys')) or '.exe' in s.lower():
            stats['has_exe']+=1
        if hex_re.match(s):
            stats['has_hash']+=1
        if uuid_re.match(s):
            stats['has_uuid']+=1
        if s.replace('.','',1).isdigit():
            if '.' in s:
                stats['has_float']+=1
            else:
                stats['has_int']+=1
        low = s.lower()
        if any(lb in low for lb in known_labels):
            stats['has_label']+=1
        if (s.startswith('[') and s.endswith(']')) or (';' in s and len(s.split(';'))>1) or ('|' in s and len(s.split('|'))>1):
            stats['has_json_like']+=1
    return stats


def main():
    job = json.load(open(JOB_PATH))
    keys_sample = job.get('debug',{}).get('rows_sample_keys') or []
    if keys_sample and isinstance(keys_sample[0], list):
        headers = keys_sample[0]
    else:
        # fallback to generic col names (length from first row)
        a = json.load(open(ASSESS_PATH))
        first = a.get('rows', [])[0]
        headers = [f'col_{i}' for i in range(len(first))]

    assess = json.load(open(ASSESS_PATH))
    rows = assess.get('rows') or []
    n = min(len(rows), SAMPLE_COUNT)

    # collect per-column samples
    col_samples = {i: [] for i in range(len(headers))}
    for i in range(n):
        r = rows[i]
        if isinstance(r, list):
            for j in range(len(r)):
                col_samples.setdefault(j,[]).append(r[j])
        elif isinstance(r, dict):
            # use header positions if keys align
            for j,h in enumerate(headers):
                col_samples.setdefault(j,[]).append(r.get(h))

    col_stats = {}
    for j,h in enumerate(headers):
        s = col_samples.get(j,[])[:n]
        col_stats[h] = detect_value_types(s)

    # score headers for likely canonical mapping
    mapping_scores = {h: {} for h in headers}
    for h,stats in col_stats.items():
        # heuristic weights
        mapping_scores[h]['file_path'] = stats['has_path']*2 + stats['has_exe']*3
        mapping_scores[h]['process_name'] = stats['has_exe']*2 + stats['has_int']
        mapping_scores[h]['sha256'] = stats['has_hash']*5
        mapping_scores[h]['uuid'] = stats['has_uuid']*4
        mapping_scores[h]['confidence'] = stats['has_float']*3 + stats['has_int']
        mapping_scores[h]['risk_label'] = stats['has_label']*5
        mapping_scores[h]['factors'] = stats['has_json_like']*4

    # pick best header for each canonical field greedily
    chosen = {}
    fields = ['sha256','file_path','process_name','confidence','risk_label','factors','uuid']
    used = set()
    for fld in fields:
        best=None; best_score=-1
        for h in headers:
            if h in used: continue
            sc = mapping_scores.get(h,{}).get(fld,0)
            if sc>best_score:
                best_score=sc; best=h
        if best and best_score>0:
            chosen[fld]=best; used.add(best)

    # produce mapped rows and run triage
    sys_path_insert = os.getcwd()
    import sys
    if sys_path_insert not in sys.path:
        sys.path.insert(0, sys_path_insert)
    from src.api.deep_analyze_endpoints import _compute_triage_score

    mapped_rows = []
    for i in range(n):
        r = rows[i]
        d = {}
        if isinstance(r, list):
            for j,v in enumerate(r):
                key = headers[j] if j < len(headers) else f'col_{j}'
                d[key]=v
        else:
            d = dict(r)
        # promote detected fields into canonical keys if mapped
        if 'sha256' in chosen:
            d['sha256'] = d.get(chosen['sha256'])
        if 'file_path' in chosen:
            d['file_path'] = d.get(chosen['file_path'])
        if 'process_name' in chosen:
            d['process_name'] = d.get(chosen['process_name'])
        if 'confidence' in chosen:
            # normalize numeric
            val = d.get(chosen['confidence'])
            try:
                v = float(val)
                # if values look like percentages >1 and <=100, normalize to 0-1
                if v>1 and v<=100:
                    v = v/100.0
                d['risk_confidence'] = v
            except Exception:
                pass
        if 'risk_label' in chosen:
            d['risk_label'] = d.get(chosen['risk_label'])
        if 'factors' in chosen:
            fv = d.get(chosen['factors'])
            if isinstance(fv,str) and fv.strip().startswith('['):
                try:
                    d['factors'] = json.loads(fv)
                except Exception:
                    d['factors'] = [x.strip() for x in fv.split(';') if x.strip()]

        mapped_rows.append(d)

    triage_scores = [_compute_triage_score(r) for r in mapped_rows]
    nonzero = sum(1 for s in triage_scores if s>0)

    print('\nDetected header stats (first sample):')
    for h,st in list(col_stats.items()):
        print(f"  {h}: {st}")
    print('\nChosen mapping:')
    pprint(chosen)
    print(f"\nTriage on first {n} rows: non-zero={nonzero}/{n}")
    print('Sample triage scores:', triage_scores[:10])
    print('\nSample mapped row (0):')
    pprint({k:mapped_rows[0].get(k) for k in list(mapped_rows[0].keys())[:40]})

if __name__=='__main__':
    main()
