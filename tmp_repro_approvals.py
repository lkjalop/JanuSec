import os, tempfile, importlib, sqlite3
from pathlib import Path
p = Path(tempfile.gettempdir())/('approvals_test_db.sqlite')
if p.exists(): p.unlink()
os.environ['APPROVAL_DB_PATH']=str(p)
os.environ['USE_APPROVAL_DB']='1'
import src.core.approval_store as approval_store
importlib.reload(approval_store)
from src.core import approval_repo
approval_repo.init_db()
approval_repo.save_policy('isolate_policy','isolate',2,3, scope={'reason':'high'}, enabled=True)

token='tok-test-nm'
approval_store.create_request(token, {'action':'isolate','target':'host-1'})
print('After request, approvals table:')
conn=sqlite3.connect(str(p))
cur=conn.cursor()
for row in cur.execute('SELECT * FROM approvals'):
    print(row)
print('\nApproval events table:')
for row in cur.execute('SELECT id, token, event_type, payload, ts FROM approval_events'):
    print(row)

approval_store.approve_token(token,'alice')
print('\nAfter 1st approve, events:')
for row in cur.execute('SELECT id, token, event_type, payload, ts FROM approval_events'):
    print(row)

approval_store.approve_token(token,'bob')
print('\nAfter 2nd approve, events:')
for row in cur.execute('SELECT id, token, event_type, payload, ts FROM approval_events'):
    print(row)

# count approvers using repo helper
print('\nget_approvers_for_token ->', approval_repo.get_approvers_for_token(token))
print('count_approvals ->', approval_repo.count_approvals(token))
print('is_approved ->', approval_store.is_approved(token))
conn.close()
