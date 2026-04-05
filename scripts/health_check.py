#!/usr/bin/env python3
import urllib.request, urllib.error, json, sys
API='http://localhost:8080'

def get(path):
    url = API + path
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            body = r.read().decode('utf-8', errors='ignore')
            return r.getcode(), body
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read().decode('utf-8', errors='ignore')
        except Exception:
            return e.code, ''
    except Exception as e:
        return 0, str(e)

if __name__=='__main__':
    code, body = get('/api/v1/health')
    print('HEALTH', code)
    if code==200:
        try:
            j = json.loads(body)
            print('health.status=', j.get('status'))
        except Exception:
            print(body[:400])
    else:
        print(body[:400])
    code, body = get('/react/index.html')
    print('/react/index.html', code)
    print(body[:400])
