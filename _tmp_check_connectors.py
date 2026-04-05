try:
    from src.api.routes import connectors
    print('OK prefix:', connectors.router.prefix)
    routes = [r.path for r in connectors.router.routes]
    print('ROUTES:', routes[:5])
except Exception as e:
    import traceback
    traceback.print_exc()
