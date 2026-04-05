import json
import requests

base='http://127.0.0.1:8080'
headers={'x-api-key':'devkey123'}

url = base + '/api/v1/csv/deep_analyze'
payload = {
    'rows': [{
        'process_name':'bad.exe',
        'host':'host-01',
        'verdict':'suspicious',
        'factors':['process_injection','unsigned_binary'],
        'row_index': 5
    }],
    'pipeline_context':{
        'request_id':'test-deep-002',
        'overrides':{
            'ollama_host':'http://localhost:11434',
            'ollama_model':'ggml-model',
            'ollama_generate_path':'/api/generate'
        }
    }
}

print('POST', url)
r = requests.post(url, json=payload, headers=headers, timeout=10)
print('Status', r.status_code)
try:
    print('JSON:', json.dumps(r.json(), indent=2))
except Exception:
    print('Response text:', r.text)
