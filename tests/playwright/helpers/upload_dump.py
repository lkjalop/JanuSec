#!/usr/bin/env python3
import sys, os, json
try:
    import requests
except Exception as e:
    print(json.dumps({'error':'requests_missing','detail':str(e)}))
    sys.exit(2)
fp = os.path.join(os.getcwd(),'dump','Cyberstash_csv2.xlsx')
if not os.path.exists(fp):
    print(json.dumps({'error':'file_missing','path':fp}))
    sys.exit(1)
url = os.environ.get('UPLOAD_URL','http://localhost:8080/api/v1/upload/files')
headers = {'x-api-key': os.environ.get('API_KEY','devkey123')}
with open(fp,'rb') as f:
    files = {'files': ('Cyberstash_csv2.xlsx', f, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')}
    try:
        r = requests.post(url, files=files, headers=headers, timeout=120)
        try:
            j = r.json()
        except Exception:
            j = {'text': r.text[:2000]}
        out = {'status': r.status_code, 'json': j}
        print(json.dumps(out))
        sys.exit(0 if r.status_code==200 else 3)
    except Exception as e:
        print(json.dumps({'error':'request_failed','detail':str(e)}))
        sys.exit(4)
