import urllib.request, json, sys

def get_health():
    url='http://127.0.0.1:8080/api/v1/llm/health'
    req=urllib.request.Request(url, headers={'x-api-key':'devkey123'})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode('utf-8')
            try:
                j=json.loads(body)
                print(json.dumps(j, indent=2))
            except Exception:
                print(body)
    except Exception as e:
        print('ERROR', e)
        return 2
    return 0

if __name__=='__main__':
    sys.exit(get_health())
