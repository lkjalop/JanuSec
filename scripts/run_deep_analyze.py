import json
import sys
import time
from urllib import request, error

BASE = 'http://localhost:8080'
API_KEY = 'devkey123'

payload = {
  "rows": [
    {"row_index": 0, "raw": {"process_name": "cmd.exe", "file_path": "C:/temp/bad.exe", "sha256": "deadbeef", "host": "host1", "user": "alice"}}
  ],
  "options": {"auto_llm": True},
  "analyze_mode": "basic"
}

def post_json(path, data):
    url = BASE + path
    b = json.dumps(data).encode('utf-8')
    req = request.Request(url, data=b, method='POST')
    req.add_header('Content-Type', 'application/json')
    req.add_header('x-api-key', API_KEY)
    try:
        with request.urlopen(req, timeout=30) as resp:
            return resp.status, json.load(resp)
    except error.HTTPError as e:
        try:
            body = e.read().decode('utf-8')
            return e.code, json.loads(body)
        except Exception:
            return e.code, {'error': str(e)}
    except Exception as e:
        return None, {'error': str(e)}

def get_json(path):
    url = BASE + path
    req = request.Request(url, method='GET')
    req.add_header('x-api-key', API_KEY)
    try:
        with request.urlopen(req, timeout=30) as resp:
            return resp.status, json.load(resp)
    except error.HTTPError as e:
        try:
            body = e.read().decode('utf-8')
            return e.code, json.loads(body)
        except Exception:
            return e.code, {'error': str(e)}
    except Exception as e:
        return None, {'error': str(e)}

if __name__ == '__main__':
    print('Posting deep_analyze payload...')
    status, resp = post_json('/api/v1/csv/deep_analyze', payload)
    print('POST status:', status)
    print(json.dumps(resp, indent=2))
    if not resp or not isinstance(resp, dict):
        print('Invalid response, aborting', file=sys.stderr); sys.exit(1)
    aid = resp.get('assessment_id') or resp.get('id') or resp.get('session_id')
    if not aid:
        print('No assessment id returned, aborting', file=sys.stderr); sys.exit(2)
    print('Assessment id:', aid)

    # Poll assessment status
    attempts = 0
    final = None
    while attempts < 120:
        attempts += 1
        st, sbody = get_json(f'/api/v1/assessments/{aid}')
        print(f'Attempt {attempts}: status_code={st}')
        if isinstance(sbody, dict) and sbody.get('status'):
            print('Status:', sbody.get('status'))
            if sbody.get('status') in ('completed', 'failed'):
                final = sbody
                break
        time.sleep(2)
    if final is None:
        print('Assessment did not complete in time', file=sys.stderr)
    else:
        print('Final assessment:')
        print(json.dumps(final, indent=2))

    # Fetch rows
    st, rows = get_json(f'/api/v1/assessments/{aid}/rows')
    print('Rows fetch status:', st)
    try:
        print(json.dumps(rows, indent=2))
    except Exception:
        print(rows)

    # Inspect for tier1/tier2 outputs
    try:
        llm_rows = None
        if final and isinstance(final, dict):
            llm_rows = final.get('llm_rows') or final.get('rows')
        if not llm_rows:
            # fallback to rows payload
            if isinstance(rows, dict) and rows.get('rows'):
                llm_rows = rows.get('rows')
            elif isinstance(rows, list):
                llm_rows = rows
        print('\nDetected LLM rows sample:')
        if llm_rows and isinstance(llm_rows, list):
            for r in llm_rows[:3]:
                print(json.dumps(r, indent=2))
        else:
            print('No LLM rows found in assessment output')
    except Exception as e:
        print('Error inspecting llm rows:', e)
