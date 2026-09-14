import os
from src.core.graph.persistence.simple_snapshot import persist_snapshot

snap = {'nodes':{'n1':{'type':'host','metadata':{'name':'h1'}}}, 'edges':[{'src':'n1','dst':'n2','etype':'connect','weight':1.0,'metadata':{}}]}
DB = os.path.join(os.getcwd(), 'tmp_debug_persist.db')
os.environ['HOPGRAPH_DB_PATH'] = DB
res = persist_snapshot('tenant-test', snap)
print('persist_snapshot returned:', res)
print('DB exists:', os.path.exists(DB), DB)
# Now inspect using sqlite3 directly
import sqlite3, json
conn = sqlite3.connect(DB)
cur = conn.cursor()
print('tables:')
for row in cur.execute("SELECT name FROM sqlite_master WHERE type='table'"):
    print(' -', row[0])
print('\nnodes:')
try:
    for r in cur.execute('SELECT id,type,label,last_seen,json_meta FROM nodes'):
        print(r[0], r[1], r[2], r[3], json.loads(r[4] or '{}'))
except Exception as e:
    print('nodes query error:', e)
print('\nedges:')
try:
    for r in cur.execute('SELECT id,src,dst,etype,last_seen,json_meta FROM edges'):
        print(r[0], r[1], r[2], r[3], r[4], json.loads(r[5] or '{}'))
except Exception as e:
    print('edges query error:', e)
print('\nwal_events:')
try:
    for r in cur.execute('SELECT id,ts,tenant,kind,payload FROM wal_events'):
        try:
            payload = json.loads(r[4] or '{}')
        except Exception:
            payload = r[4]
        print(r[0], r[1], r[2], r[3], payload)
except Exception as e:
    print('wal_events query error:', e)
print('\nsnapshot_meta:')
try:
    for r in cur.execute('SELECT id,snapshot_id,saved_seq_max,edge_version,ts FROM snapshot_meta'):
        print(r)
except Exception as e:
    print('snapshot_meta query error:', e)
conn.close()