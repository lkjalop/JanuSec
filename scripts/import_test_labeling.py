import importlib
for name in ('src.api.labeling_endpoints','src.api.admin_calibration'):
    try:
        m = importlib.import_module(name)
        print(name, 'imported, has router:', hasattr(m, 'router'))
    except Exception as e:
        print(name, 'import failed:', type(e).__name__, str(e))
