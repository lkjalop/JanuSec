import json,urllib.request,sys
body = {
    "rows": [
        {"process_name": "evilproc.exe", "host": "host1", "user": "analyst", "factors": ["suspicious_process"]}
    ],
    "options": {"auto_llm": True},
    "overrides": {"ollama_host": "http://localhost:11434", "ollama_model": "ggml-model", "ollama_generate_path": "/api/generate"}
}

data = json.dumps(body).encode('utf-8')
req = urllib.request.Request('http://127.0.0.1:8090/api/v1/assessments/deep_analyze', data=data, headers={'Content-Type': 'application/json'})
try:
    resp = urllib.request.urlopen(req, timeout=30)
    print('STATUS', resp.status)
    print(resp.read().decode('utf-8'))
except Exception as e:
    print('ERROR', e, file=sys.stderr)
