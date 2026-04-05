import urllib.request
import urllib.error
import json, sys

url='http://127.0.0.1:8080/api/v1/insights/generate?args=[]&kwargs={}'
payload={
    'insight_type':'tier1',
    'row':{
        'verdict':'SUSPICIOUS',
        'host':'WKS-OLLAMA',
        'process_name':'rundll32.exe',
        'factors':['unsigned_executable','lolbin'],
        'triage_score': 0.6,
        'sha256':'cafebabecafebabecafebabecafebabecafebabecafebabecafebabe'
    },
    'pipeline_context':{
        'overrides':{
            'ollama_host':'http://127.0.0.1:11434',
            'ollama_model':'llama3:8b',
            'ollama_generate_path':'/api/generate'
        }
    }
}
data=json.dumps(payload).encode('utf-8')
headers = {'x-api-key':'devkey123','Content-Type':'application/json','X-Roles':'analyst'}
req=urllib.request.Request(url, data=data, headers=headers)
try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode('utf-8')
        print(body[:4000])
except urllib.error.HTTPError as e:
    try:
        print('HTTP', e.code, e.read().decode())
    except Exception:
        print('HTTP', e.code)
except Exception as e:
    print('ERR', e)
    