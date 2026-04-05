import os
os.environ['DKIM_HISTORY_PATH'] = 'C:/Windows/Temp/dh_test.json'
from src.core.enrichment.dkim_history import record_dkim_result, get_last_dkim, _path
print('path:', _path())
record_dkim_result('alice@example.com', True, 'example.com', ts=1690000000)
print('get:', get_last_dkim('alice@example.com'))
print('file exists?', os.path.exists(_path()))
try:
    with open(_path(),'r',encoding='utf-8') as fh:
        print(fh.read())
except Exception as e:
    print('read error', e)
