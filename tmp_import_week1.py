import importlib
print('importing week1 module...')
try:
    importlib.import_module('src.core.correlation.rules.week1.office_macro_chain')
    print('import succeeded')
except Exception as e:
    print('import failed', e)

from src.core.correlation.rules.registry import CORRELATION_RULES
print('registered rules count', len(CORRELATION_RULES.list()))
print([r.name for r in CORRELATION_RULES.list()][:200])
