import sys, traceback
sys.path.insert(0, '.')
try:
    import src.api.connector_admin_endpoints as mod
    print('imported ok, has _SECRETS_PATH?', hasattr(mod,'_SECRETS_PATH'))
    print('secrets path value:', getattr(mod,'_SECRETS_PATH', None))
except Exception as e:
    print('import failed:', e)
    traceback.print_exc()
