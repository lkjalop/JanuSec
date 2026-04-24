import requests, json
url = 'http://127.0.0.1:8080/api/v1/llm/settings'
headers = {'x-api-key': 'devkey123', 'content-type': 'application/json'}
payload = {'ollama_base_url': 'http://127.0.0.1:11434', 'ollama_model': 'qwen2.5:14b'}
try:
    r = requests.post(url, json=payload, headers=headers, timeout=15)
    print('STATUS', r.status_code)
    try:
        print(r.json())
    except Exception:
        print(r.text)
except Exception as e:
    print('ERR', e)
