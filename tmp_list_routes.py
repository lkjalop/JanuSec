import os
os.environ.setdefault('PLATFORM_LITE_INIT','1')
os.environ.setdefault('TEST_HELPERS_ENABLED','1')
os.environ.setdefault('DISABLE_DB','1')
from src.api.app import app
routes = sorted([(getattr(r,'path',str(r)), getattr(r,'methods',None), getattr(r,'endpoint',None)) for r in app.router.routes], key=lambda x: x[0])
print('ASK_FOR_LOGS_PRESENT', any(p == '/api/v1/reports/{report_id}/ask_for_logs' for p,_,_ in routes))
print('HAS_ASK_FOR_LOGS_EXACT', any(p == '/api/v1/reports/rep-123/ask_for_logs' for p,_,_ in routes))
print('TOTAL_ROUTES', len(routes))
for p,m,e in routes[:200]:
    print(p)
