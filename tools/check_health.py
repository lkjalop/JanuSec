import requests,sys
try:
    r = requests.get('http://localhost:8080/api/v1/health', timeout=5)
    print('HTTP', r.status_code)
    print(r.text)
except Exception as e:
    print('ERR', e)
    sys.exit(2)
