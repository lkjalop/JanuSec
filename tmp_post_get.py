import requests
url='http://localhost:8080/api/v1/admin/connectors/config/purview'
headers={'x-api-key':'devkey123'}
print('POSTing...')
resp = requests.post(url, headers=headers, json={'config':{'test_field':'manual-test'}})
print('POST', resp.status_code, resp.text)
resp2 = requests.get(url, headers=headers)
print('GET', resp2.status_code, resp2.text)
