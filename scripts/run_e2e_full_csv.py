import requests, json, time
from pathlib import Path
BASE='http://127.0.0.1:18081'
HEADERS={'x-api-key':'devkey123'}

csv_path = Path('dump/csv_from_excel/Cyberstash_csv2_in.csv')
if not csv_path.exists():
    print('CSV missing:', csv_path)
    raise SystemExit(2)

# read all rows but avoid insane memory; we'll stream in chunks for creation
BATCH_SIZE = 500
rows = []
cols = None
count = 0
with csv_path.open('r', encoding='utf-8', errors='ignore') as f:
    header = f.readline().strip().split(',')
    cols = header
    for line in f:
        vals = [v.strip() for v in line.strip().split(',')]
        rows.append(vals)
        count += 1

print('Read', count, 'rows')
# Send all rows in one create request (server seems to accept reasonable sizes)
body = {'rows': rows, 'cols': cols}
print('Posting create (rows:', len(rows), ')')
resp = requests.post(BASE + '/api/v1/csv/deep_analyze', headers=HEADERS, json=body, timeout=120)
print('create resp', resp.status_code)
print(resp.text[:1000])
if resp.status_code != 200:
    print('Create failed; aborting')
    raise SystemExit(3)

j = resp.json()
aid = j.get('assessment_id') or j.get('report_id') or j.get('id')
print('Assessment id:', aid)

print('Starting auto_backfill for assessment')
resp2 = requests.post(BASE + '/api/v1/csv/deep_analyze/auto_backfill', headers=HEADERS, json={'assessment_id':aid}, timeout=30)
print('start backfill', resp2.status_code, resp2.text)

# Poll status until completed or timeout and capture timeline
timeline = []
start = time.time()
while True:
    st = requests.get(BASE + f'/api/v1/csv/deep_analyze/auto_backfill/{aid}/status', headers=HEADERS, timeout=10)
    t = time.time() - start
    try:
        js = st.json()
    except Exception:
        js = {'raw': st.text}
    timeline.append({'t': t, 'status_code': st.status_code, 'body': js})
    print('t=%.1f status=%s' % (t, js.get('status')))
    # break on completion or reasonable timeout
    if isinstance(js, dict) and js.get('status') in ('completed','stopping','cancelled'):
        break
    if t > 300:
        print('Timeout waiting for backfill (300s)')
        break
    time.sleep(2)

out = Path('dump/csv_from_excel/backfill_timeline.json')
out.write_text(json.dumps(timeline, indent=2))
print('Wrote timeline to', out)
print('Final status:', timeline[-1])
