import sys
sys.path.insert(0, '.')
import importlib
try:
    m = importlib.import_module('src.api.supply_chain_endpoints')
    print('imported', m, 'router=', getattr(m,'router',None))
except Exception as e:
    print('import error', e)
