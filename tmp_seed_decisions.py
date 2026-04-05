import requests
url='http://localhost:8080/api/v1/dev/seed_decisions'
payload = {"count": 2, "prefix": "seed", "tenant_id": "demo"}
resp = requests.post(url, json=payload, headers={'x-api-key': 'devkey123'})
print(resp.status_code)
print(resp.text)
