import time
import json
import requests

base='http://127.0.0.1:8080'
headers={'x-api-key':'devkey123'}

# Tier1 test
url_t1=base+'/api/v1/insights/generate'
payload_t1={
  'insight_type':'tier1',
  'row':{
    'process_name':'bad.exe',
    'host':'host-01',
    'verdict':'suspicious',
    'factors':['process_injection','unsigned_binary'],
    'row_index': 5
  },
  'pipeline_context':{
    'request_id':'test-tier1-004',
    'overrides':{
      'ollama_host':'http://localhost:11434',
      'ollama_model':'ggml-model',
      'ollama_generate_path':'/api/generate'
    }
  }
}

# Deep analyze (Tier2) test
url_t2=base+'/api/v1/assessments/csv/deep_analyze'
payload_t2={
  'rows': [payload_t1['row']],
  'pipeline_context':{
    'request_id':'test-deep-001',
    'overrides':{
      'ollama_host':'http://localhost:11434',
      'ollama_model':'ggml-model',
      'ollama_generate_path':'/api/generate'
    }
  }
}

# wait for server
for i in range(20):
    try:
        r = requests.get(base + '/api/v1/status', timeout=1)
        if r.status_code==200:
            print('Server is up')
            break
    except Exception:
        pass
    time.sleep(0.5)

print('POST', url_t1)
r = requests.post(url_t1, json=payload_t1, headers=headers, timeout=10)
print('Status', r.status_code)
try:
    print('JSON:', json.dumps(r.json(), indent=2))
except Exception:
    print('Response text:', r.text)

print('\nPOST', url_t2)
r2 = requests.post(url_t2, json=payload_t2, headers=headers, timeout=10)
print('Status', r2.status_code)
try:
    print('JSON:', json.dumps(r2.json(), indent=2))
except Exception:
    print('Response text:', r2.text)
