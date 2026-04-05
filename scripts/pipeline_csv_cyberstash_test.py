import os, sys, json, time, pathlib
import requests

BASE = os.environ.get('TEST_SERVER_URL', 'http://localhost:8080')
API = BASE.rstrip('/')
HEADERS = {'x-api-key': os.environ.get('API_KEY','devkey123')}

_default_xlsx = os.path.join(os.getcwd(), 'dump', 'Cyberstash_csv2.xlsx')
_default_csv = os.path.join(os.getcwd(), 'dump', 'Cyberstash_csv2_sample.csv')
DUMP_FILE = os.environ.get('DUMP_FILE') or (_default_csv if os.path.exists(_default_csv) else _default_xlsx)

def upload_tabular(path):
    ext = pathlib.Path(path).suffix.lower()
    if ext == '.csv':
        mime = 'text/csv'
    elif ext in ('.xlsx', '.xlsm', '.xltx', '.xltm'):
        mime = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    else:
        mime = 'application/octet-stream'
    files = [('files', (os.path.basename(path), open(path, 'rb'), mime))]
    r = requests.post(f"{API}/api/v1/upload/tabular", files=files, headers=HEADERS)
    r.raise_for_status()
    return r.json()

def deep_analyze_csv(rows, mapping=None, auto_llm=False):
    payload = {
        'rows': rows,
        'mapping': mapping or {},
        'options': {'auto_llm': bool(auto_llm)},
        'org': os.environ.get('ORG','demo')
    }
    r = requests.post(f"{API}/api/v1/assessments/csv/deep_analyze", json=payload, headers=HEADERS)
    r.raise_for_status()
    return r.json()

def generate_llm(aid, limit=25):
    r = requests.post(f"{API}/api/v1/assessments/generate_llm_summaries", json={'assessment_id': aid, 'limit': int(limit)}, headers=HEADERS)
    r.raise_for_status()
    return r.json()

if __name__ == '__main__':
    print('[pipeline] Using server', API)
    if not os.path.exists(DUMP_FILE):
        print('[error] Missing file:', DUMP_FILE)
        sys.exit(1)
    print('[upload] Posting', DUMP_FILE)
    up = upload_tabular(DUMP_FILE)
    rows = up.get('results') or []
    print('[upload] Parsed rows:', len(rows))
    # Fallback: if CSV and server returned only a single sample row, parse locally for richer analysis
    try:
        ext = pathlib.Path(DUMP_FILE).suffix.lower()
    except Exception:
        ext = ''
    if ext == '.csv' and len(rows) <= 1:
        import csv
        local_rows = []
        with open(DUMP_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for i, r in enumerate(reader):
                # Normalize keys to strings; skip entirely empty rows
                if not any(v for v in r.values()):
                    continue
                local_rows.append({str(k): r[k] for k in r.keys()})
                if i >= 999:
                    break
        if local_rows:
            rows = local_rows
            print('[fallback] Locally parsed CSV rows:', len(rows))
    # Build simple mapping guess
    sample = rows[0] if rows else {}
    mapping = {}
    for k in list(sample.keys()):
        lk = str(k).lower()
        if 'process' in lk or 'exe' in lk: mapping.setdefault('process', k)
        elif 'path' in lk or 'file' in lk: mapping.setdefault('file_path', k)
        elif 'sha256' in lk or 'hash' in lk: mapping.setdefault('file_hash', k)
        elif 'host' in lk or 'endpoint' in lk: mapping.setdefault('host', k)
        elif lk in ('user','username','account'): mapping.setdefault('user', k)
        elif 'domain' in lk: mapping.setdefault('domain', k)
    print('[mapping]', mapping)
    print('[assess] Creating assessment (auto_llm off)')
    assess = deep_analyze_csv(rows[:400], mapping=mapping, auto_llm=False)
    aid = assess.get('assessment_id') or assess.get('id')
    print('[assess] id=', aid)
    if not aid:
        print('[error] No assessment id returned')
        sys.exit(1)
    # Fetch rows for DREAD & top6
    rr = requests.get(f"{API}/api/v1/assessments/{aid}/rows", headers=HEADERS)
    rr.raise_for_status()
    data = rr.json()
    orig_rows = data.get('rows') or []
    def _score(row):
        try:
            d = row.get('_dread') or row.get('dread') or {}
            return float(d.get('score') or 0.0)
        except Exception:
            return 0.0
    sorted_rows = sorted(orig_rows, key=_score, reverse=True)
    top6 = sorted_rows[:6]
    print('[dread] top6 scores:', [round(_score(r),2) for r in top6])
    # --- FAIR-shadow computation (non-invasive) ---
    def compute_fair(rows):
        # Simple heuristic-based FAIR shadow overlay. Returns aggregate metrics and persona notes.
        LM_BUCKET_TO_VALUE = {1:1000,2:10000,3:50000,4:200000,5:1000000}
        total_expected_loss = 0.0
        row_summaries = []
        missing_canonical = 0
        for i, r in enumerate(rows):
            raw = r.get('raw') or r
            # Check canonical fields
            has_user = bool(raw.get('user') or raw.get('username') or raw.get('account'))
            has_host = bool(raw.get('host') or raw.get('hostname'))
            has_process = bool(raw.get('process') or raw.get('process_name'))
            has_hash = bool(raw.get('sha256') or raw.get('file_hash'))
            has_domain = bool(raw.get('domain'))
            if not (has_user and has_host and (has_process or has_hash or has_domain)):
                missing_canonical += 1

            # TEF proxy
            tef = 0.05
            if raw.get('public_ip') or raw.get('exposure') or raw.get('url'):
                tef += 0.35
            if raw.get('scan_count'):
                try:
                    sc = float(raw.get('scan_count') or 0)
                    if sc>10: tef += 0.1
                except Exception:
                    pass
            if raw.get('asn') or raw.get('epx') or raw.get('kev'):
                tef += 0.05

            # PoA proxy
            poa = 0.05
            if raw.get('kev') or raw.get('exploit_available') or raw.get('cve'):
                poa += 0.4
            if raw.get('targeted') or raw.get('threat_actor'):
                poa += 0.2

            # Resistance Strength estimate
            rs = 0.2
            if raw.get('edr') or raw.get('has_edr'):
                rs += 0.25
            if raw.get('mfa') or raw.get('has_mfa'):
                rs += 0.15
            if raw.get('patched') or raw.get('is_patched'):
                rs += 0.2
            if rs>0.95: rs = 0.95

            # Susceptibility
            susc = max(0.01, 1.0 - rs)

            # LEF = TEF * PoA * CF proxy (use tef*poa as simple aggregate)
            lef = tef * poa

            # LM bucket heuristic
            lm_bucket = 2
            if raw.get('sensitive') or raw.get('sensitivity')=='high':
                lm_bucket = 4
            if raw.get('customer_impact') or raw.get('num_records'):
                try:
                    nr = int(raw.get('num_records') or 0)
                    if nr>10000: lm_bucket = max(lm_bucket,4)
                    elif nr>1000: lm_bucket = max(lm_bucket,3)
                except Exception:
                    pass

            lm_value = LM_BUCKET_TO_VALUE.get(lm_bucket,10000)

            expected_loss = lef * susc * lm_value
            total_expected_loss += expected_loss

            row_summaries.append({
                'row_index': r.get('row_index'),
                'lef': round(lef,5),
                'susc': round(susc,3),
                'lm_bucket': lm_bucket,
                'expected_loss': round(expected_loss,2)
            })

        # Aggregate personas
        n = len(rows) or 1
        data_sufficiency = 1.0 - (missing_canonical / n)
        exec_summary = {
            'annualized_expected_loss': round(total_expected_loss,2),
            'data_sufficiency': round(data_sufficiency,3),
            'note': 'LEF and LM are provisional; increase canonical fields to improve fidelity.'
        }
        grc = {
            'data_sufficiency_pct': round(data_sufficiency*100,1),
            'finding': 'Missing canonical fields for audit-quality quantification' if data_sufficiency<0.8 else 'Sufficient canonical coverage'
        }
        soc = {
            'operational_priority': 'low' if total_expected_loss<5000 else 'medium',
            'cues': []
        }
        owner = {
            'business_impact_uncertain': True,
            'recommendations': ['Capture user/host/process/file_hash/domain', 'Add reputation feeds (EPSS/KEV/ASN)']
        }

        return {'exec': exec_summary, 'grc': grc, 'soc': soc, 'owner': owner, 'rows': row_summaries}

    fair = compute_fair(orig_rows)
    print('[fair] exec.annualized_expected_loss:', fair['exec']['annualized_expected_loss'], 'data_sufficiency:', fair['exec']['data_sufficiency'])
    # Now trigger LLM summaries (Tier1/Tier2 flow defaults)
    try:
        gen = generate_llm(aid, limit=25)
        print('[llm] queued summaries for assessment', aid)
    except Exception as e:
        print('[llm] generation error:', e)
    # Fetch assessment snapshot including llm_rows if present
    snap = requests.get(f"{API}/api/v1/assessments/{aid}", headers=HEADERS).json()
    llm_rows = snap.get('llm_rows') or []
    t1 = [r for r in llm_rows if not r.get('tier') or r.get('tier')=='tier1'][:6]
    t2 = [r for r in llm_rows if r.get('tier')=='tier2'][:6]
    print('[llm] tier1 count:', len(t1), 'tier2 count:', len(t2))
    # Print concise output for report
    out = {
        'assessment_id': aid,
        'mapping': mapping,
        'top6_dread': [{
            'score': round(_score(r),3),
            'process': r.get('process_name') or r.get('process') or (r.get('raw') or {}).get('process'),
            'host': r.get('host') or (r.get('raw') or {}).get('host'),
            'sha256': r.get('sha256') or (r.get('raw') or {}).get('sha256'),
            'verdict': r.get('verdict') or r.get('decision')
        } for r in top6],
        'tier1_summaries': [{
            'row_index': r.get('row_index'),
            'verdict': r.get('verdict'),
            'risk_label': r.get('risk_label'),
            'top_factors': (r.get('factors') or [])[:4],
            'recommendation': r.get('recommendation') or (r.get('recommendations') or []),
        } for r in t1],
        'tier2_explains': [{
            'row_index': r.get('row_index'),
            'verdict': r.get('verdict'),
            'llm_summary': r.get('llm_summary'),
            'mapping_semantics': r.get('mapping_semantics'),
            'kill_chain': r.get('kill_chain'),
        } for r in t2],
    }
    print(json.dumps(out, indent=2))
