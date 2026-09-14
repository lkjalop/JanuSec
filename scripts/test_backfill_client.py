import time, requests, json
base='http://localhost:8080'
headers={'x-api-key':'devkey123','Content-Type':'application/json'}
# create a small assessment via /api/v1/csv/deep_analyze
rows=[{'row_index':i,'raw':{'EventID':f'e{i}','data':'x'}} for i in range(8)]
payload={'rows':rows,'options':{'auto_llm':False},'org':'local'}
print('POST /api/v1/csv/deep_analyze')
r=requests.post(base+'/api/v1/csv/deep_analyze', json=payload, headers=headers)
print('status', r.status_code)
print(r.text[:400])
if not r.ok:
    raise SystemExit('failed create')
j=r.json()
aid=j.get('assessment_id') or j.get('id')
print('assessment id:', aid)
# start auto backfill
print('POST start backfill')
r2=requests.post(base+'/api/v1/csv/deep_analyze/auto_backfill', json={'assessment_id':aid}, headers=headers)
print('start status', r2.status_code)
print(r2.text[:400])
# poll status a few times
for i in range(20):
    time.sleep(1)
    rs = requests.get(base+f'/api/v1/csv/deep_analyze/auto_backfill/{aid}/status', headers=headers)
    print('poll', i, rs.status_code)
    try:
        s=rs.json()
        print('  state=', s.get('state'), 'progress=', s.get('progress'))
        if 'eta_seconds' in s and s['eta_seconds'] is not None:
            print('  ETA seconds seen:', s['eta_seconds'])
            break
    except Exception as e:
        print('  json err', e)
# stop
print('POST stop')
r3=requests.post(base+f'/api/v1/csv/deep_analyze/auto_backfill/{aid}/stop', headers=headers)
print('stop status', r3.status_code)
print(r3.text[:400])
