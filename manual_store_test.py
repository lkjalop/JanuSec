import os, sqlite3
os.environ['SESSION_BACKEND']='sqlite'
os.environ['SESSION_PERSIST_SQLITE_PATH']=r'C:/Users/Kevin J/AppData/Local/Temp/manual_store_sessions.db'
from src.api.session_store import get_session_store, reset_session_store
reset_session_store()
store = get_session_store()
print('Store type', type(store))
print('DB path', store.db_path)
# verify table exists
conn = sqlite3.connect(store.db_path)
cur = conn.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
print('tables', cur.fetchall())
conn.close()
