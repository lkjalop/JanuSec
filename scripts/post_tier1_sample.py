import urllib.request
import urllib.request
import urllib.error
import json, sys

def post_tier1():
    url='http://127.0.0.1:8080/api/v1/insights/generate?args=[]&kwargs={}'
    payload={
        'insight_type':'tier1',
        'row':{
            'verdict':'SUSPICIOUS',
            'host':'WKS-01',
            'process_name':'rundll32.exe',
            'factors':['unsigned_executable','lolbin','novel_local'],
            'triage_score': 0.5,
            'sha256':'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
        },
        'pipeline_context':{}
    }
    data=json.dumps(payload).encode('utf-8')
    headers = {'x-api-key':'devkey123','Content-Type':'application/json','X-Roles':'analyst'}
    req=urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode('utf-8')
            try:
                j=json.loads(body)
                print(json.dumps(j, indent=2)[:4000])
            except Exception:
                print(body)
    except Exception as e:
        if isinstance(e, urllib.error.HTTPError):
            try:
                err_body = e.read().decode('utf-8', errors='ignore')
            except Exception:
                err_body = '<no body>'
            print('HTTPError', e.code)
            try:
                jb = json.loads(err_body)
                print(json.dumps(jb, indent=2)[:4000])
            except Exception:
                print(err_body)
            return 2
        print('ERROR', e)
        return 2
    return 0

if __name__=='__main__':
    sys.exit(post_tier1())
