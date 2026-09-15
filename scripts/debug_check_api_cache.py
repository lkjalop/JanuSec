import importlib, sys, os
# ensure package import path
if os.path.abspath('api') not in sys.path:
    sys.path.insert(0, os.path.abspath('.'))
import api.server as svr
import src.api.runtime_state as rs
print('ids:', id(svr.DECISION_CACHE), id(rs.DECISION_CACHE))
# set via runtime_state
rs.cache_set('evt-test', {'event_id':'evt-test','verdict':'allow','confidence':0.5,'factors':[]})
print('server.get(evt-test)=', svr.DECISION_CACHE.get('evt-test'))
