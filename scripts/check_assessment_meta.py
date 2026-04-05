import requests, json
url = 'http://127.0.0.1:8080/api/v1/graph/session/build'
payload = { 'session_ids': ['acme-e2e-1'], 'correlate': True, 'ewma': True }
resp = requests.post(url, json=payload)
print('status', resp.status_code)
try:
    j = resp.json()
    print('has_assessment_meta', 'assessment_meta' in j)
    if 'assessment_meta' in j:
        print(json.dumps(j['assessment_meta'], indent=2))
    else:
        # print top-level keys
        print('keys:', list(j.keys()))
except Exception as e:
    print('resp_text', resp.text)
