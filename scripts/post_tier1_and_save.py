import urllib.request
import urllib.error
import json
import sys
from pathlib import Path

OUT = Path('data') / 'tier1_sample_response.json'
OUT.parent.mkdir(parents=True, exist_ok=True)

def post_and_save():
    url='http://127.0.0.1:8080/api/v1/insights/generate?args=[]&kwargs={}'
    payload={
        'insight_type':'tier1',
        'row':{
            'verdict':'SUSPICIOUS',
            'host':'WKS-01',
            'process_name':'rundll32.exe',
            'factors':['unsigned_executable','lolbin','novel_local'],
            'triage_score': 0.6,
            'sha256':'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
        },
        'pipeline_context':{}
    }
    data=json.dumps(payload).encode('utf-8')
    headers = {'x-api-key':'devkey123','Content-Type':'application/json','X-Roles':'analyst'}
    req=urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode('utf-8')
            j = None
            try:
                j = json.loads(body)
            except Exception:
                j = {'text': body}
            OUT.write_text(json.dumps(j, indent=2))
            print('Saved', OUT)
            return 0
    except urllib.error.HTTPError as e:
        try:
            eb = e.read().decode('utf-8')
        except Exception:
            eb = '<no body>'
        print('HTTPError', e.code)
        print(eb)
        return 2
    except Exception as e:
        print('ERROR', e)
        return 2

if __name__=='__main__':
    sys.exit(post_and_save())
import os
import json
import sys
import urllib.request
import urllib.error

def ensure_dir(path):
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)

def post_and_save(out_path='data/tier1_sample_response.json'):
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
        'pipeline_context':{ }
    }
    data=json.dumps(payload).encode('utf-8')
    headers = {'x-api-key':'devkey123','Content-Type':'application/json','X-Roles':'analyst'}
    req=urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode('utf-8')
            try:
                j = json.loads(body)
            except Exception:
                j = {'raw_text': body}
            ensure_dir(out_path)
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(j, f, indent=2)
            print('Saved response to', out_path)
            print(json.dumps(j, indent=2)[:4000])
            return 0
    except Exception as e:
        if isinstance(e, urllib.error.HTTPError):
            try:
                err_body = e.read().decode('utf-8', errors='ignore')
            except Exception:
                err_body = '<no body>'
            err = {'http_error': e.code, 'body': err_body}
            ensure_dir(out_path)
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(err, f, indent=2)
            print('HTTPError', e.code)
            print(err_body)
            return 2
        print('ERROR', e)
        return 3

if __name__ == '__main__':
    out = 'data/tier1_sample_response.json'
    if len(sys.argv) > 1:
        out = sys.argv[1]
    sys.exit(post_and_save(out))
import urllib.request
import urllib.error
import json
import sys
from pathlib import Path

OUT = Path('data') / 'tier1_sample_response.json'
OUT.parent.mkdir(parents=True, exist_ok=True)

def post_and_save():
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
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode('utf-8')
            try:
                j=json.loads(body)
            except Exception:
                j={'raw': body}
            OUT.write_text(json.dumps(j, indent=2))
            print('Saved response to', OUT)
            return 0
    except Exception as e:
        if isinstance(e, urllib.error.HTTPError):
            try:
                err_body = e.read().decode('utf-8', errors='ignore')
            except Exception:
                err_body = '<no body>'
            print('HTTPError', e.code)
            print(err_body)
            return 2
        print('ERROR', e)
        return 2

if __name__=='__main__':
    sys.exit(post_and_save())
import urllib.request
import urllib.error
import json, sys, os

OUT_PATH = os.path.join('data', 'tier1_sample_response.json')

def post_and_save():
    os.makedirs('data', exist_ok=True)
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
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode('utf-8')
            try:
                j=json.loads(body)
            except Exception:
                j={'raw': body}
            with open(OUT_PATH, 'w', encoding='utf-8') as f:
                json.dump(j, f, indent=2)
            print('Saved response to', OUT_PATH)
            print(json.dumps(j, indent=2)[:4000])
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
    sys.exit(post_and_save())
