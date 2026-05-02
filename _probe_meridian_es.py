import urllib.request, json, time

aid = 'assessment-1777722364-d804376b'
t0 = time.time()
print('Calling exec summary regenerate=True...')
req = urllib.request.Request(
    f'http://localhost:8080/api/v1/assessments/{aid}/executive-summary',
    data=json.dumps({'regenerate': True, 'model': 'qwen3:14b'}).encode(),
    headers={'x-api-key':'devkey123','x-tenant-id':'default','Content-Type':'application/json'},
    method='POST'
)
try:
    r = json.loads(urllib.request.urlopen(req, timeout=300).read().decode())
    elapsed = time.time() - t0
    print(f'Done in {elapsed:.0f}s')
    print('from_cache:', r.get('from_cache'))
    print('headline:', r.get('headline','')[:120])
    print('exec_len:', len(r.get('executive_summary','')))
    print('narrative_provenance:', r.get('narrative_provenance'))
    print('rollup_provenance:', r.get('rollup_provenance'))
    cs = r.get('cluster_summaries', [])
    print(f'clusters: {len(cs)}')
    for c in cs:
        cid = c.get('cluster_id','?')
        prov = c.get('provenance','?')
        claims = len(c.get('claims',[]))
        witnesses = len(c.get('control_witnesses',[]))
        sev = c.get('severity','?')
        print(f'  {cid}: sev={sev} prov={prov} claims={claims} witnesses={witnesses}')
    ps = r.get('persona_summaries', {})
    print(f'personas: {list(ps.keys())}')
    for k, v in ps.items():
        # persona_summaries is {persona: [list of PersonaNarrative dicts]}
        if isinstance(v, list):
            total_txt = sum(len(pn.get('summary','')) for pn in v if isinstance(pn,dict))
            total_ctrls = sum(len(pn.get('control_failures',[])) for pn in v if isinstance(pn,dict))
            print(f'  {k}: summary_total_len={total_txt} control_failures_total={total_ctrls}')
        elif isinstance(v, dict):
            print(f'  {k}: len={len(v.get("summary",""))} control_failures={len(v.get("control_failures",[]))}')
        else:
            print(f'  {k}: {type(v).__name__} len={len(str(v))}')
except Exception as e:
    print(f'FAILED: {e}')
