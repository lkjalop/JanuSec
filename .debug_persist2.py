import os, time, json, traceback
from src.pipeline.deep_analyze_pipeline import DEFAULT_WORKER
s = DEFAULT_WORKER.status('test-session-debug')
print('session present', bool(s))
try:
    payload = s.get('payload') or {}
    assessment_id = payload.get('assessment_id') or payload.get('session_id') or None
    org = payload.get('org') or 'unknown'
    rows = payload.get('rows') or []
    llm_rows = []
    try:
        from src.analysis.auto_llm import build_llm_row
    except Exception as e:
        print('import auto_llm failed', e)
        build_llm_row = None
    if build_llm_row:
        for r in rows:
            try:
                llm_rows.append(build_llm_row(r, {'auto_llm': payload.get('options', {}).get('auto_llm', False)}))
            except Exception as e:
                print('build row failed', e)
    if assessment_id:
        try:
            repo_root = os.getcwd()
            datepart = time.strftime('%Y-%m-%d', time.gmtime(time.time()))
            base = os.getenv('SESSION_PERSIST_DIR') or os.path.join(repo_root, 'data', 'assessments')
            dest = os.path.join(base, org, datepart)
            print('dest=',dest)
            os.makedirs(dest, exist_ok=True)
            path = os.path.join(dest, f"{assessment_id}.json")
            out = {'assessment_id': assessment_id, 'session_id': 'test-session-debug', 'org': org, 'summary': s.get('summary'), 'llm_rows': llm_rows}
            with open(path + '.tmp', 'w', encoding='utf-8') as fh:
                fh.write(json.dumps(out))
            os.replace(path + '.tmp', path)
            print('wrote', path)
        except Exception:
            traceback.print_exc()
except Exception:
    traceback.print_exc()
