import os, importlib
import tempfile
td = tempfile.TemporaryDirectory()
path = os.path.join(td.name, 'emitted_factors.log')
os.environ['EMITTED_FACTORS_LOG_PATH'] = path
print('EMITTED_FACTORS_LOG_PATH=', path)
ev = importlib.import_module('src.api.routes.events')
print('events._emit_factor:', getattr(ev, '_emit_factor', None))
try:
    ev._emit_factor('prompt_injection', decision_id='evt-probe')
    print('called _emit_factor')
except Exception as e:
    print('call raised', e)
print('file exists?', os.path.exists(path))
if os.path.exists(path):
    print('contents:\n', open(path,'r',encoding='utf-8').read())
