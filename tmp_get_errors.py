import requests
url='http://localhost:8080/api/v1/debug/last-errors'
try:
    r = requests.get(url)
    print(r.status_code)
    print(r.text)
except Exception as e:
    print('ERR', e)
