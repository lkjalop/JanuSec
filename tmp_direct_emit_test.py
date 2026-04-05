import os, importlib, tempfile, json
os.environ['EMITTED_FACTORS_LOG_PATH'] = 'tmp_emitted.log'
mod = importlib.import_module('src.api.routes.events')
print('module loaded, has _emit_factor=', hasattr(mod,'_emit_factor'))
mod._emit_factor('prompt_injection', decision_id='dec-1')
print('wrote, contents:')
with open('tmp_emitted.log','r',encoding='utf-8') as fh:
    print(fh.read())
