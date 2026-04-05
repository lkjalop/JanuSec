import requests
url='http://localhost:8080/api/v1/decisions/recent'
resp = requests.get(url, headers={'x-api-key': 'devkey123'})
print('STATUS', resp.status_code)
print(resp.text)
