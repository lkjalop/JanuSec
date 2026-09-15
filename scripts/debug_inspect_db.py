import sqlite3, sys, json
p = sys.argv[1] if len(sys.argv)>1 else None
if not p:
    print('Usage: python debug_inspect_db.py <db_path>')
    sys.exit(2)
conn = sqlite3.connect(p)
cur = conn.cursor()
print('tables:')
for row in cur.execute("SELECT name FROM sqlite_master WHERE type='table'"):
    print('  ', row[0])
print('\nnodes:')
for r in cur.execute('SELECT id,type,label,last_seen,json_meta FROM nodes'):
    print(r[0], r[1], r[2], r[3], json.loads(r[4] or '{}'))
print('\nedges:')
for r in cur.execute('SELECT id,src,dst,etype,last_seen,json_meta FROM edges'):
    print(r[0], r[1], r[2], r[3], r[4], json.loads(r[5] or '{}'))
print('\nwal_events:')
for r in cur.execute('SELECT id,ts,tenant,kind,payload FROM wal_events'):
    try:
        payload = json.loads(r[4] or '{}')
    except Exception:
        payload = r[4]
    print(r[0], r[1], r[2], r[3], payload)
print('\nsnapshot_meta:')
for r in cur.execute('SELECT id,snapshot_id,saved_seq_max,edge_version,ts FROM snapshot_meta'):
    print(r)
conn.close()