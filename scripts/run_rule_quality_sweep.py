"""Run a rule-quality sweep across registered correlation rules.

Behavior:
- Loads rule metadata from src/core/correlation/rules/rules_metadata.json and prioritized_backlog.json
- For each registered rule, finds referenced test vector file paths (if present) and loads them from the repo `tests/data` tree
- If no real vector exists, synthesizes a minimal placeholder vector using the rule's `factors_required` hints
- Evaluates the rule via `CORRELATION_RULES.evaluate` and records whether it fired, any exceptions, and which vectors triggered it
- Writes `data/rule_quality_report.json` and `data/rule_quality_report.csv`

Run:
    python scripts/run_rule_quality_sweep.py
"""
import json
import os
import csv
import traceback
from typing import Any, Dict, List


def load_json(path):
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        return None


def synthesize_vector(factors: List[str]) -> Dict[str, Any]:
    v: Dict[str, Any] = {}
    # base realistic defaults
    for f in factors:
        key = f.lower()
        if key in ('process','proc_name','process_name'):
            v[f] = 'notepad.exe'
        elif 'cmd' in key or 'command' in key or 'cmdline' in key:
            # realistic command lines: powershell encoded, curl|bash, or simple exec
            if 'powershell' in key or 'pwsh' in key or 'encoded' in key:
                v[f] = 'powershell -nop -w hidden -encodedcommand SGVsbG8='
            else:
                v[f] = 'cmd.exe /c whoami'
        elif 'user' in key:
            v[f] = 'alice'
        elif 'domain' in key or key.endswith('tld'):
            v[f] = 'example-rare-xyz.tld'
        elif 'ip' in key:
            v[f] = '203.0.113.45'
        elif any(tok in key for tok in ('count','num','size','bytes','http_bytes','ftp_upload_bytes')):
            v[f] = 150000
        elif any(tok in key for tok in ('path','file','dmp','dump','file_path','dmp_file')):
            v[f] = 'C:/Windows/Temp/suspicious.dmp'
        elif 'lsass' in key or 'dump' in key:
            # set several lsass-related flags for credential rules
            v[f] = True
            v.setdefault('lsass_handle_open', True)
            v.setdefault('dump_file_created', True)
        elif 'token' in key or 'imperson' in key:
            v[f] = True
            v.setdefault('impersonation', True)
            v.setdefault('impersonation_chain', ['explorer.exe','svchost.exe'])
        elif key.startswith('net:') or ':' in key:
            v[f] = True
        elif any(x in key for x in ('ransom','mass_rename','vss','distinct_extensions')):
            if 'file_rename_count' in key or 'rename' in key:
                v[f] = 150
            else:
                v[f] = True
        else:
            v[f] = True
    # Always include an event id for hopgraph lookups
    v.setdefault('event_id', 'synth-0001')
    return v


def main():
    # Ensure repo root is importable
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    if repo_root not in __import__('sys').path:
        __import__('sys').path.insert(0, repo_root)

    # import registry
    try:
        from src.core.correlation.rules.registry import CORRELATION_RULES
    except Exception:
        print('Failed to import CORRELATION_RULES')
        traceback.print_exc()
        return 2

    # load metadata files
    rules_meta = load_json(os.path.join('src','core','correlation','rules','rules_metadata.json')) or []
    backlog = load_json(os.path.join('src','core','correlation','rules','prioritized_backlog.json')) or []

    # map rule id -> test_vectors from metadata/backlog
    vectors_map = {}
    for ent in rules_meta:
        rid = ent.get('id')
        tv = ent.get('test_vectors') or []
        if rid:
            vectors_map.setdefault(rid, []).extend(tv)
    for ent in backlog:
        rid = ent.get('id')
        tv = ent.get('tests') or ent.get('test_vectors') or []
        if rid and tv:
            vectors_map.setdefault(rid, []).extend(tv)

    # Allow local overrides: data/custom_test_vectors.json (mapping rule -> [paths])
    overrides = load_json(os.path.join('data','custom_test_vectors.json')) or {}
    if isinstance(overrides, dict):
        for rid, tvs in overrides.items():
            if isinstance(tvs, list) and tvs:
                vectors_map.setdefault(rid, []).extend(tvs)

    # prepare report
    report = []
    os.makedirs('data', exist_ok=True)

    regs = CORRELATION_RULES.list()
    print(f'Found {len(regs)} registered rules; sweeping...')

    for r in regs:
        rid = getattr(r, 'name', getattr(r, 'id', None))
        factors = getattr(r, 'factors_required', []) or []
        severity = getattr(r, 'severity', None)
        confidence = getattr(r, 'confidence_boost', None)
        candidate_vectors = vectors_map.get(rid, [])
        evaluated = []
        fired_any = False
        errors = []

        if not candidate_vectors:
            # synthesize one placeholder vector
            vec = synthesize_vector(factors)
            candidate_vectors = [None]
        for cv in candidate_vectors:
            try:
                if cv:
                    # try the path as-provided first (handles metadata that already
                    # contains a tests/... prefix), then try multiple likely test
                    # data dirs
                    candidate_path = None
                    if isinstance(cv, str) and os.path.exists(cv):
                        candidate_path = cv
                    else:
                        for base in ('tests/data', 'tests/data/auto_audit', 'tests/data/vectors'):
                            p = os.path.join(base, cv)
                            if os.path.exists(p):
                                candidate_path = p
                                break
                    if candidate_path:
                        with open(candidate_path, 'r', encoding='utf-8') as fh:
                            vec = json.load(fh)
                    else:
                        # fallback to synthesized vector
                        vec = synthesize_vector(factors)
                # evaluate
                fired = CORRELATION_RULES.evaluate(vec)
                fired_names = [x.name for x in fired]
                fired_flag = bool(any(x == rid or x == getattr(r,'id',None) for x in fired_names))
                evaluated.append({'vector': cv or '<synthesized>', 'fired': fired_flag, 'fired_names': fired_names})
                if fired_flag:
                    fired_any = True
            except Exception as ex:
                tb = traceback.format_exc()
                errors.append({'vector': cv or '<synthesized>', 'error': tb})

        report.append({'rule': rid, 'source_module': getattr(r, 'source_module', None), 'factors_required': factors, 'severity': severity, 'confidence_boost': confidence, 'tested_vectors': evaluated, 'fired_any': fired_any, 'errors': errors})

    # generate mismatch report: rules that had a real vector file but did not fire
    mismatch = []
    for ent in report:
        for tv in ent['tested_vectors']:
            vec = tv.get('vector')
            if vec and isinstance(vec, str) and vec.startswith('tests/') and not tv.get('fired'):
                mismatch.append({'rule': ent['rule'], 'vector': vec, 'source_module': ent.get('source_module'), 'severity': ent.get('severity'), 'confidence_boost': ent.get('confidence_boost'), 'fired': False})

    # produce simple suggestions by comparing vector keys to required factors
    suggestions = []
    for m in mismatch:
        try:
            p = os.path.join(m['vector'])
            if os.path.exists(p):
                with open(p, 'r', encoding='utf-8') as fh:
                    vec_data = json.load(fh)
            else:
                vec_data = {}
        except Exception:
            vec_data = {}
        # find rule entry in report
        ent = next((x for x in report if x['rule'] == m['rule']), None)
        req = ent.get('factors_required') if ent else []
        present = list(vec_data.keys()) if isinstance(vec_data, dict) else []
        # simple mapping suggestions: if present key shares substring with required key
        map_sugg = []
        for rkey in req:
            for pkey in present:
                if rkey.lower().replace('_','') in pkey.lower().replace('_','') or pkey.lower().replace('_','') in rkey.lower().replace('_',''):
                    map_sugg.append({'from': pkey, 'to': rkey})
        suggestions.append({'rule': m['rule'], 'vector': m['vector'], 'present_keys': present, 'required_keys': req, 'suggested_mappings': map_sugg})

    mismatch_path = os.path.join('data','rule_mismatch_report.json')
    suggest_path = os.path.join('data','rule_suggestions.json')
    with open(mismatch_path, 'w', encoding='utf-8') as fh:
        json.dump(mismatch, fh, indent=2)
    with open(suggest_path, 'w', encoding='utf-8') as fh:
        json.dump(suggestions, fh, indent=2)

    # write JSON and CSV
    json_path = os.path.join('data','rule_quality_report.json')
    csv_path = os.path.join('data','rule_quality_report.csv')
    with open(json_path, 'w', encoding='utf-8') as fh:
        json.dump(report, fh, indent=2)

    # CSV columns: rule,fired_any,num_vectors,num_fired,errors
    with open(csv_path, 'w', encoding='utf-8', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['rule','source_module','fired_any','num_vectors','num_fired','errors'])
        for ent in report:
            num_vectors = len(ent['tested_vectors'])
            num_fired = sum(1 for v in ent['tested_vectors'] if v.get('fired'))
            errs = len(ent.get('errors') or [])
            w.writerow([ent['rule'], ent.get('source_module'), ent['fired_any'], num_vectors, num_fired, errs])

    print('Sweep complete. Reports:')
    print(' -', json_path)
    print(' -', csv_path)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
