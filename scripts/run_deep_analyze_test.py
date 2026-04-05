import requests, time, json, sys

API = 'http://127.0.0.1:8080'

def submit_and_poll(n=20, wait=1):
    rows = []
    for i in range(n):
        rows.append({'id': f'r{i}', 'cols': {'user': f'user{i%5}', 'host': f'host{i%4}', 'process': 'cmd.exe' if i%2==0 else 'powershell', 'domain': f'example{i}.bad'}, 'row_index': i})
    payload = {'source': 'test-big', 'rows': rows, 'auto_llm': True, 'limit': n}
    t0 = time.time()
    # Deep analyze endpoint lives under /api/v1/csv/deep_analyze
    r = requests.post(API + '/api/v1/csv/deep_analyze', json=payload, timeout=120)
    t1 = time.time()
    print('submit status', r.status_code, 'submit_elapsed', round(t1-t0,2))
    try:
        res = r.json()
    except Exception:
        print('response not json:', r.text[:1000])
        return 1
    aid = res.get('assessment_id')
    print('assessment_id', aid)
    if not aid:
        return 1
    prog_url = f"{API}/api/v1/assessments/{aid}/llm/progress"
    start = time.time()
    last = None
    for i in range(300):
        pr = requests.get(prog_url, timeout=10)
        try:
            pj = pr.json()
        except Exception:
            pj = {'text': pr.text}
        ts = time.time()
        succeeded = pj.get('succeeded', 0)
        failed = pj.get('failed', 0)
        queued = pj.get('queued', 0)
        processing = pj.get('processing', 0)
        print(f'[{i}] time={round(ts-start,1)} suc={succeeded} fail={failed} queued={queued} proc={processing}')
        sys.stdout.flush()
        if succeeded + failed >= n:
            print('done in', round(ts-start,2), 'succeeded', succeeded, 'failed', failed)
            break
        time.sleep(wait)
    return 0

if __name__ == '__main__':
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    rc = submit_and_poll(n=n)
    sys.exit(rc)
