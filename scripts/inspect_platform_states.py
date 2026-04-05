import sys, os
sys.path.insert(0, '.')
import importlib
import pkgutil

found = []
for name in list(sys.modules.keys()):
    try:
        m = sys.modules.get(name)
        if not m:
            continue
        ps = getattr(m, '_PLATFORM_STATE', None)
        if ps is not None:
            found.append((name, id(ps)))
    except Exception:
        pass

# Also try to import commonly referenced modules
candidates = ['src.api.dependencies','src.api.alerts_endpoints','src.api.server','src.api.routes.events','src.api.state']
for c in candidates:
    try:
        m = importlib.import_module(c)
        ps = getattr(m, '_PLATFORM_STATE', None)
        if ps is not None:
            found.append((c, id(ps)))
    except Exception:
        pass

print('Found platform states:')
for n,i in sorted(found):
    print(n, i)

# Compare to canonical in dependencies
try:
    deps = importlib.import_module('src.api.dependencies')
    print('deps._PLATFORM_STATE id', id(getattr(deps, '_PLATFORM_STATE')))
except Exception as e:
    print('deps import failed', e)

# Check alerts_endpoints ALERT_RING and _PLATFORM_STATE
try:
    a = importlib.import_module('src.api.alerts_endpoints')
    print('alerts_mod.ALERT_RING id', id(getattr(a, 'ALERT_RING', None)), 'len', len(getattr(a, 'ALERT_RING', [])))
    print('alerts_mod._PLATFORM_STATE', getattr(a, '_PLATFORM_STATE', None))
except Exception as e:
    print('alerts import failed', e)
