import requests, json
url='http://127.0.0.1:11434/api/generate'
payload={'model':'llama3:8b','prompt':'Hello from test','stream':False,'options':{'num_predict':50}}
resp = requests.post(url, json=payload, timeout=10)
print('Status', resp.status_code)
try:
    print(json.dumps(resp.json(), indent=2))
except Exception:
    print(resp.text)
