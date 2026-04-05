from src.api.app import app
for r in app.routes:
    if '/forward/backlog_report' in getattr(r, 'path', '') or '/forwarding/backlog' in getattr(r, 'path', ''):
        print('Route', r.path, getattr(r, 'name', None), 'methods', r.methods)
        try:
            from inspect import signature
            print('endpoint', r.endpoint)
            print('sig', signature(r.endpoint))
        except Exception as e:
            print('sig err', e)
        print('---')
