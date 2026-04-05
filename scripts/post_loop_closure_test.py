import json, urllib.request, urllib.error
base='http://localhost:8080'
aid='assessment-1764584415-bf178b89'
# fetch assessment to build payload
try:
    req=urllib.request.Request(base+f'/api/v1/assessments/{aid}', headers={'x-api-key':'devkey123'})
    with urllib.request.urlopen(req, timeout=10) as r:
        ass = json.load(r)
except Exception as e:
    print('Failed to fetch assessment:', e)
    raise SystemExit(2)
row = ass.get('llm_rows', [])[0]
summary = row.get('llm_summary') or 'no summary'
incident = {
    'artifact_id': f'row-{row.get("row_index")}',
    'title': f'Auto Incident - row {row.get("row_index")}',
    'description': summary,
    'attack_subgraph': { 'nodes': [], 'edges': [] }
}
# POST incident
inc_url = base + '/api/v1/incidents'
inc_data = json.dumps(incident).encode('utf8')
inc_headers = {'Content-Type':'application/json','x-api-key':'devkey123','X-Tenant-ID':'local'}
req = urllib.request.Request(inc_url, data=inc_data, headers=inc_headers, method='POST')
try:
    with urllib.request.urlopen(req, timeout=10) as r:
        print('INCIDENT STATUS', r.status)
        print(r.read().decode('utf8'))
except urllib.error.HTTPError as e:
    print('INCIDENT HTTP ERROR', e.code)
    try:
        print(e.read().decode('utf8'))
    except:
        pass
except Exception as e:
    print('INCIDENT REQUEST FAILED', e)

# POST SBOM
sbom = { 'components': [ { 'name': f'example-from-row-{row.get("row_index")}', 'version': '0.0.1', 'purl': 'pkg:generic/example@0.0.1' } ] }
sb_data = json.dumps(sbom).encode('utf8')
sb_url = base + '/api/v1/sbom/upload'
sb_headers = {'Content-Type':'application/json','x-api-key':'devkey123','X-Tenant-ID':'local'}
req = urllib.request.Request(sb_url, data=sb_data, headers=sb_headers, method='POST')
try:
    with urllib.request.urlopen(req, timeout=10) as r:
        print('SBOM STATUS', r.status)
        print(r.read().decode('utf8'))
except urllib.error.HTTPError as e:
    print('SBOM HTTP ERROR', e.code)
    try:
        print(e.read().decode('utf8'))
    except:
        pass
except Exception as e:
    print('SBOM REQUEST FAILED', e)
