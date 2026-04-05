import requests, json
url = 'http://127.0.0.1:8080/api/v1/insights/generate'
headers = {'Content-Type': 'application/json', 'x-api-key': 'devkey123'}
body = {
    'insight_type': 'tier1',
    'row': {'id': 'r1', 'text': 'this is a test row for ollama override'},
    'pipeline_context': {
        'request_id': 'test-tier1-ollama-py',
        'overrides': {
            'ollama_host': 'http://127.0.0.1:11434',
            'ollama_model': 'llama3:8b',
            'ollama_generate_path': '/api/generate'
        }
    },
    'provider': 'ollama'
}
print('Posting to', url)
resp = requests.post(url, headers=headers, data=json.dumps(body))
print('Status:', resp.status_code)
try:
    print('Response JSON:', json.dumps(resp.json(), indent=2))
except Exception:
    print('Response text:', resp.text)
