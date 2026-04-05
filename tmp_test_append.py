import os, sqlite3
from pathlib import Path
p = Path('d:\\AI\\Threat_thy_sniffer\\test_append_db.sqlite')
if p.exists(): p.unlink()
os.environ['APPROVAL_DB_PATH']=str(p)
from src.core import approval_repo

# initialize DB and insert a request row
approval_repo.init_db()
approval_repo.save_request('tok1', {'action':'isolate'}, None)
print('Events before:')
conn = sqlite3.connect(str(p))
cur = conn.cursor()
for r in cur.execute('SELECT id,token,event_type,payload,ts FROM approval_events'):
    print(r)

# try to append approve event directly and catch exceptions
try:
    approval_repo.append_event('tok1','approve',{'approver':'alice'})
    print('append_event succeeded')
except Exception as e:
    import traceback
    traceback.print_exc()

print('Events after:')
for r in cur.execute('SELECT id,token,event_type,payload,ts FROM approval_events'):
    print(r)
conn.close()
