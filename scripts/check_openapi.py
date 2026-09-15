import urllib.request, json, sys

def fetch_openapi():
    url='http://127.0.0.1:8080/openapi.json'
    req=urllib.request.Request(url, headers={'x-api-key':'devkey123'})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode('utf-8')
            j=json.loads(body)
            paths = j.get('paths', {})
            for p in sorted(paths.keys()):
                if 'llm' in p or 'insight' in p or 'insights' in p:
                    print(p)
            # print summary
            print('\nTotal paths:', len(paths))
    except Exception as e:
        print('ERROR', e)
        return 2
    return 0

if __name__=='__main__':
    sys.exit(fetch_openapi())
