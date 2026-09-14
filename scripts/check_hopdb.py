import sqlite3
import os

p = 'data/sessions/hopgraph.db'
print('hop db path:', p)
print('exists:', os.path.exists(p))
if not os.path.exists(p):
    print('DB file not found')
    raise SystemExit(1)
con = sqlite3.connect(p)
cur = con.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
tables = [r[0] for r in cur.fetchall()]
print('tables:', tables)
for t in tables:
    try:
        cur.execute(f"SELECT count(*) FROM {t}")
        print(f"{t}:", cur.fetchone()[0])
    except Exception as e:
        print('error reading table', t, e)
con.close()
