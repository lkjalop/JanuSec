import requests, json, sys
url='http://localhost:8080/api/v1/llm/prewarm'
payload={'model':'llama3:8b','tokens':8}
try:
    r = requests.post(url, json=payload, timeout=120)
    print('STATUS', r.status_code)
    try:
        print(json.dumps(r.json(), indent=2))
    except Exception:
        print(r.text)
    with open('sim_reports/prewarm_response.json','w',encoding='utf8') as f:
        try:
            json.dump(r.json(), f, indent=2)
        except Exception:
            f.write(r.text)
except Exception as e:
    print('ERROR', e)
    sys.exit(1)
