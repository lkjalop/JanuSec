import requests, time, json
BASE='http://127.0.0.1:18081'
aid='assessment-1764489749-250532ab'
headers={'x-api-key':'devkey123'}
print('Starting backfill for', aid)
resp = requests.post(BASE+f'/api/v1/csv/deep_analyze/auto_backfill', json={'assessment_id':aid,'target_coverage':0.2,'window_seconds':2,'batch_size':20}, headers=headers, timeout=10)
print('start resp', resp.status_code, resp.text)
for i in range(10):
    try:
        st = requests.get(BASE+f'/api/v1/csv/deep_analyze/auto_backfill/{aid}/status', headers=headers, timeout=10)
        print(i, 'status', st.status_code)
        j = st.json()
        print(' processed', j.get('processed'), 'total', j.get('total'), 'candidate_count', j.get('debug',{}).get('candidate_count'), 'coverage', j.get('coverage'))
    except Exception as e:
        print('status err', e)
    time.sleep(2)
# final read of job file
try:
    with open('data/sessions/backfill_jobs/'+aid+'.json','r',encoding='utf-8') as fh:
        j=json.load(fh)
    print('job snapshot:', json.dumps(j, indent=2)[:1000])
except Exception as e:
    print('read job err', e)
# inspect first 20 rows of assessment
try:
    with open('data/assessments/unknown/2025-11-30/'+aid+'.json','r',encoding='utf-8') as fh:
        txt=fh.read()
    a=json.loads(txt)
    rows=a.get('rows') or []
    print('rows count', len(rows))
    for r in rows[:20]:
        if isinstance(r, dict):
            print('row_index',r.get('row_index'),'_pipeline_done',r.get('_pipeline_done'),'keys',list(r.keys())[:12])
        else:
            print('raw list row',r[:6])
except Exception as e:
    print('read assessment err', e)
