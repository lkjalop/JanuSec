import importlib
is_mod = importlib.import_module('src.api.incidents_store')
print('incidents_store module:', is_mod, id(is_mod))
print('INCIDENT_STORE id:', id(getattr(is_mod, 'INCIDENT_STORE', None)))
sm = importlib.import_module('src.api.server')
print('server._INCIDENT_STORE id:', id(sm.__dict__.get('_INCIDENT_STORE')))
