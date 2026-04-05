import requests, sys
url = 'http://localhost:8080/api/v1/csv/debug/deep_pipeline_error'
try:
    r = requests.get(url, timeout=5)
    print(r.status_code)
    try:
        print(r.json())
    except Exception:
        print(r.text)
except Exception as e:
    print('request_failed', e)
    sys.exit(2)
