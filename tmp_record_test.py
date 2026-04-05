import os, tempfile, importlib
td = tempfile.TemporaryDirectory()
path = os.path.join(td.name, 'emitted_factors.log')
os.environ['EMITTED_FACTORS_LOG_PATH'] = path
print('ENV set to', path)
mod = importlib.import_module('src.core.factors.emission_tracker')
print('module _LOG_PATH attr exists?', getattr(mod, '_LOG_PATH', None))
mod.record_emission('prompt_injection', decision_id='evt-1')
print('wrote, exists?', os.path.exists(path))
if os.path.exists(path):
    print('contents:\n', open(path,'r',encoding='utf-8').read())
