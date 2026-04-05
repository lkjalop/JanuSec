import requests, json, os

os.makedirs('sim_reports', exist_ok=True)
url='http://localhost:8080/api/v1/llm/prewarm'
payload={'model':'llama3:8b','tokens':8}
try:
    r = requests.post(url, json=payload, timeout=120)
    with open('sim_reports/prewarm_headers.txt','w',encoding='utf8') as f:
        f.write(str(r.status_code)+'\n')
        for k,v in r.headers.items(): f.write(f'{k}: {v}\n')
    with open('sim_reports/prewarm_response.json','w',encoding='utf8') as f:
        try:
            json.dump(r.json(), f, indent=2)
        except Exception:
            f.write(r.text)
    print('WROTE sim_reports/prewarm_response.json', r.status_code)
except Exception as e:
    print('ERROR', e)
