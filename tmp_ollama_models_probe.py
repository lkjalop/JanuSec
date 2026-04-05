import requests
host='http://127.0.0.1:11434'
paths=['/api/models','/api/list','/models','/v1/models','/api/version']
for p in paths:
    try:
        r = requests.get(host.rstrip('/')+p, timeout=5)
        print(p, r.status_code)
        print((r.text or '')[:1000])
    except Exception as e:
        print(p, 'ERR', e)
