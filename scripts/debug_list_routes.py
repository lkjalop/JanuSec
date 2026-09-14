from src.api.app import app
routes = sorted([getattr(r,'path',None) for r in app.router.routes])
print('has_labeling:', '/api/v1/metrics/labeling' in routes)
for p in routes:
	if p and p.startswith('/api/v1/metrics'):
		print(p)
