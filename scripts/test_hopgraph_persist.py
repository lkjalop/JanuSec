import os
os.environ.setdefault('HOPGRAPH_PERSISTENCE_ENABLED','true')
os.environ.setdefault('HOPGRAPH_DB_PATH','data/sessions/hopgraph.db')
from src.core.graph.hopgraph_lite import HopGraphLite
import time

hg = HopGraphLite()
print('backend:', type(hg.backend) if hg.backend else None)
# Ensure we have backend
hg.ensure_backend()
print('backend after ensure:', type(hg.backend) if hg.backend else None)
# Observe a sample event with user/host and auth edge
evt = {'user':'alice','host':'host-01','edge_type':'auth'}
hg.observe(evt)
print('observed event')
# Inspect DB
import sqlite3
con = sqlite3.connect(os.path.abspath(os.environ.get('HOPGRAPH_DB_PATH','data/sessions/hopgraph.db')))
cur = con.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
print('tables:', cur.fetchall())
try:
    cur.execute('SELECT count(*) FROM nodes')
    print('nodes count', cur.fetchone()[0])
    cur.execute('SELECT count(*) FROM edges')
    print('edges count', cur.fetchone()[0])
except Exception as e:
    print('read error', e)
con.close()
