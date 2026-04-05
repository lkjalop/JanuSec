import os, sys, importlib
os.environ['PLATFORM_LITE_INIT']='1'
os.environ['FAST_TEST_MODE']='1'
import tempfile
td = tempfile.TemporaryDirectory()
path = os.path.join(td.name, 'emitted_factors.log')
os.environ['EMITTED_FACTORS_LOG_PATH']=path
print('EMITTED_FACTORS_LOG_PATH:', os.environ['EMITTED_FACTORS_LOG_PATH'])
import pkgutil
found = []
for name, mod in list(sys.modules.items()):
    if not name:
        continue
    if name.endswith('emission_tracker') or 'emission_tracker' in name:
        print('MODULE:', name, '->', mod)
        try:
            lp = getattr(mod, '_LOG_PATH', None)
            print('  _LOG_PATH=', lp)
        except Exception as e:
            print('  _LOG_PATH err', e)
        try:
            fn = getattr(mod, 'get_emitted', None)
            print('  get_emitted callable?', callable(fn))
        except Exception as e:
            print('  get_emitted err', e)

# Now import src.api.app to ensure modules loaded
app_mod = importlib.import_module('src.api.app')
print('imported app module:', app_mod)
for name, mod in list(sys.modules.items()):
    if 'emission_tracker' in (name or ''):
        print('AFTER IMPORT MODULE:', name, '->', getattr(mod, '_LOG_PATH', None))
import sys
mods = []
for name, mod in list(sys.modules.items()):
    try:
        if not mod:
            continue
        store = getattr(mod, '_INCIDENT_STORE', None)
        if isinstance(store, list):
            mods.append((name, len(store), mod))
    except Exception:
        continue
mods.sort()
print('Found modules with _INCIDENT_STORE:')
for name, l, mod in mods:
    print(name, l)
# Also show whether 'src.api.server' and 'api.server' present and their ids
for n in ('src.api.server','api.server'):
    m = sys.modules.get(n)
    print(n, 'present' if m else 'missing', 'id=' + (hex(id(m)) if m else 'None'))
# Print the id of current module for reference
import importlib
try:
    cur = importlib.import_module('src.api.server')
    print('src.api.server id', hex(id(cur)))
except Exception as e:
    print('src.api.server import failed', e)
try:
    cur2 = importlib.import_module('api.server')
    print('api.server id', hex(id(cur2)))
except Exception as e:
    print('api.server import failed', e)
