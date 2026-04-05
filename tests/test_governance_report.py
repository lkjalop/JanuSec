import asyncio

from core.hunt.sidecar_session import get_sidecar_manager


async def _prep_sessions():
    mgr = get_sidecar_manager()
    # Create a couple of sessions to populate promotion candidates & trends
    mgr.start('gov_sess_1','tenantA',24,False)
    mgr.start('gov_sess_2','tenantA',24,False)
    mgr.start('gov_sess_3','tenantB',24,False)

async def _call_endpoint():
    from src.api.server import detections_governance_report
    return await detections_governance_report(limit_trends=10, min_sessions=1, top_n=10)

def test_governance_report_structure():
    asyncio.run(_prep_sessions())
    report = asyncio.run(_call_endpoint())
    assert 'summary' in report
    assert 'trends' in report
    assert 'promotion_candidates' in report
    assert 'effective_severity_weight_overrides' in report
    assert 'meta' in report
