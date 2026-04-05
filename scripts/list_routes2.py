import sys
sys.path.insert(0, r'D:\AI\Threat_thy_sniffer')
from src.api.app import app
paths = sorted({getattr(r,'path',str(r)) for r in app.router.routes})
print('HAS AB INSERT:', '/api/v1/metrics/ab_test/result' in paths)
print('HAS AB ANALYSIS:', '/api/v1/metrics/ab/analysis' in paths)
print('HAS DAILY PRECISION:', '/api/v1/metrics/precision/daily' in paths)
print('COUNT:', len(paths))
for p in paths:
    if 'ab' in p:
        print('AB PATH:', p)