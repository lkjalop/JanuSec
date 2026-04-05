import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / 'src'))
from fastapi.testclient import TestClient
from api.app import app
client = TestClient(app)
path = ROOT / 'dump' / 'Cyberstash_csv2.xlsx'
files = {'files': (path.name, path.read_bytes(), 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')}
r = client.post('/api/v1/upload/files', files=files, headers={'x-api-key': 'devkey123'})
js = r.json(); ana = js['results'][0]['analysis']; headers = ana['headers']; full_rows = ana.get('full_rows') or []
idx = {h: i for i, h in enumerate(headers)}
get = lambda row,k: (str(row[idx[k]]) if k in idx and idx[k] < len(row) else '').strip()
# Collect distributions
from collections import Counter
threatName = Counter(); threatScore_pos = 0; unknown = 0
for row in full_rows:
    t = get(row, 'threatName')
    if t: threatName[t] += 1
    try:
        sc = float(get(row, 'threatScore') or '0')
        if sc > 0: threatScore_pos += 1
    except Exception:
        pass
    if (get(row,'unknown').lower()=='true'):
        unknown += 1
print('THREATNAME_TOP', threatName.most_common(5))
print('THREAT_SCORE_POSITIVE', threatScore_pos)
print('UNKNOWN_TRUE', unknown)
