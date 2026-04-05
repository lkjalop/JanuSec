from src.api.app import app
paths = sorted({getattr(r,'path',str(r)) for r in app.router.routes})
print('/api/v1/admin/connectors/policies' in paths)
print([p for p in paths if 'connectors' in p][:40])
