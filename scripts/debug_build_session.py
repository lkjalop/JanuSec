import asyncio
from src.api import graph_sessions
payload = {'session_ids': ['batch-overlap-1','batch-overlap-2'], 'correlate': True, 'ewma': False, 'mapping': {'user':'user'}}
res = asyncio.get_event_loop().run_until_complete(graph_sessions.build_session(payload))
summary = res.get('summary') or res
print('factors count:', len(summary.get('factors') or []))
for f in (summary.get('factors') or []):
    print(type(f), f)
print('mapping_semantics_score:', summary.get('mapping_semantics_score'))
print('domain_diversity_score:', summary.get('domain_diversity_score'))
print('confidence_breakdown:', summary.get('confidence_breakdown'))
