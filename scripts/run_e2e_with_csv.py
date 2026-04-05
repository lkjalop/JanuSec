import requests, json, time
from pathlib import Path
BASE='http://127.0.0.1:18081'
HEADERS={'x-api-key':'devkey123'}

csv_path = Path('dump/csv_from_excel/Cyberstash_csv2_in.csv')
if not csv_path.exists():
    print('CSV missing:', csv_path)
    raise SystemExit(2)

# read rows streaming, send first N rows to create assessment
BATCH_SIZE = 200
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
        if len(rows) >= BATCH_SIZE:
            break

print('Preparing to POST', len(rows), 'rows (header cols:', len(cols), ')')
body = {'rows': rows, 'cols': cols}
resp = requests.post(BASE + '/api/v1/csv/deep_analyze', headers=HEADERS, json=body, timeout=30)
print('create resp', resp.status_code)
print(resp.text)
if resp.status_code != 200:
    print('Create failed; aborting')
    raise SystemExit(3)

j = resp.json()
aid = j.get('assessment_id') or j.get('assessment_id') or j.get('report_id') or j.get('id')
print('Assessment id:', aid)
print('Starting auto_backfill for assessment')
resp2 = requests.post(BASE + '/api/v1/csv/deep_analyze/auto_backfill', headers=HEADERS, json={'assessment_id':aid}, timeout=10)
print('start backfill', resp2.status_code, resp2.text)

# Poll status until completed or timeout
start = time.time()
while True:
    st = requests.get(BASE + f'/api/v1/csv/deep_analyze/auto_backfill/{aid}/status', headers=HEADERS, timeout=5)
    print('status', st.status_code, st.text)
    if st.status_code==200:
        s = st.json().get('status')
        if s in ('completed','stopping','cancelled'):
            break
    if time.time() - start > 60:
        print('Timeout waiting for backfill')
        break
    time.sleep(2)

print('Done')
