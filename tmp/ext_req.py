import requests
print('GET external config')
try:
    r = requests.get('http://127.0.0.1:8080/api/v1/config/assessment_defaults', headers={'x-api-key':'devkey123'})
    print(r.status_code, r.text[:200])
except Exception as e:
    print('err', e)
print('POST external assessments')
try:
    r2 = requests.post('http://127.0.0.1:8080/api/v1/assessments/save_metadata', json={'org':'acme','assessor':'alice','ts':1700000000}, headers={'x-api-key':'devkey123'})
    print(r2.status_code, r2.text[:200])
except Exception as e:
    print('err2', e)
