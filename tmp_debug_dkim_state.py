import os
os.environ['DKIM_HISTORY_PATH'] = 'C:/Windows/Temp/dh_test.json'
from src.core.enrichment import dkim_history
print('before load:', dkim_history._load_all())
dkim_history.record_dkim_result('alice@example.com', True, 'example.com', ts=1690000000)
print('after load:', dkim_history._load_all())
print('cache keys:', list(dkim_history._CACHE.keys()))
print('cache content:', dkim_history._CACHE.get(dkim_history._path()))
