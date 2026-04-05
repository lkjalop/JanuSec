import asyncio
import os
import json
import pytest

from src.api import csv_endpoints as csv_ep


@pytest.mark.asyncio
async def test_backfill_prioritizes_by_triage(tmp_path, monkeypatch):
    # set a short persist dir
    monkeypatch.setenv('SESSION_PERSIST_DIR', str(tmp_path))

    aid = 'autorank-test-assessment'

    # prepare an assessment in the deep_analyze REPORT_STORE with three rows
    try:
        from src.api import deep_analyze_endpoints as deep_ep
    except Exception:
        deep_ep = None

    rows = [
        {'row_index': 0, 'triage_score': 0.10, 'marker': 'low'},
        {'row_index': 1, 'triage_score': 0.90, 'marker': 'high'},
        {'row_index': 2, 'triage_score': 0.50, 'marker': 'mid'},
    ]

    # populate the authoritative store so _run_backfill can read it
    if deep_ep is not None:
        deep_ep.REPORT_STORE[aid] = {'assessment_id': aid, 'rows': [dict(r) for r in rows]}
        try:
            import api.deep_analyze_endpoints as alt_deep  # type: ignore
            alt_deep.REPORT_STORE[aid] = {'assessment_id': aid, 'rows': [dict(r) for r in rows]}
        except Exception:
            pass

    async def fake_run_deep(payload):
        # mark those rows as processed/ready in the authoritative store so coverage increases
        try:
            st = deep_ep.REPORT_STORE.get(aid) or {}
            rs = st.get('rows') or []
            idx_map = {int(r.get('row_index')): r for r in rs}
            for sent in payload.get('rows', []):
                try:
                    ridx = int(sent.get('row_index'))
                except Exception:
                    continue
                if ridx in idx_map:
                    idx_map[ridx]['status'] = 'ready'
            # write back
            st['rows'] = list(idx_map.values())
            deep_ep.REPORT_STORE[aid] = st
        except Exception:
            pass
        return {}

    # monkeypatch the deep pipeline to our fake
    monkeypatch.setattr('src.api.deep_analyze_endpoints.run_deep_analyze_pipeline', fake_run_deep)

    # Run the backfill worker once with batch_size equal to all rows and window_seconds 0
    await csv_ep._run_backfill(aid, target=1.0, window_seconds=0, batch_size=3, tenant_id=None, api_key=None)

    job = csv_ep.BACKFILL_JOBS.get(aid) or {}
    ordered = job.get('test_last_payload_rows') or []
    assert ordered, 'test shortcut did not record any payload rows'
    assert ordered == [1, 2, 0], f'Expected order [1,2,0] got {ordered}'
