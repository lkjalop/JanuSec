import requests, time
for i in range(20):
    try:
        r = requests.get('http://127.0.0.1:8080/api/v1/health', timeout=2)
        print('status', r.status_code)
        print(r.text[:400])
        break
    except Exception as e:
        print('probe failed', i, str(e))
        time.sleep(1)
