import os
import tempfile
import sqlite3
import json
import asyncio
from src.ml.closed_loop_manager import ClosedLoopManager


def test_closed_loop_e2e(tmp_path):
    # Ensure platform DB disabled so manager uses local sqlite file
    os.environ['USE_PLATFORM_DB'] = '0'
    # create a dedicated DB path
    db_path = tmp_path / 'clm.db'
    clm = ClosedLoopManager(db_path=str(db_path))

    # Add synthetic feedback
    clm.add_feedback('evt-1', ['factor_a','factor_b'], 1)
    # ensure learner ready
    assert clm.ready_to_learn() in (True, False)

    # Propose weights (call the async method)
    res = asyncio.get_event_loop().run_until_complete(clm.propose_weights())
    assert 'candidate' in res
    cand_id = res.get('candidate_id')

    # List candidates
    cands = clm.list_candidates()
    assert isinstance(cands, list)
    assert len(cands) >= 1

    # Approve candidate
    # provide actor and no current_weights to trigger auto-fetch
    applied = clm.approve_candidate(cands[0]['id'], actor='tester')
    assert isinstance(applied, dict)
    # Verify audit entry exists in DB
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM factor_weight_audit")
    cnt = cur.fetchone()[0]
    conn.close()
    assert cnt >= 1
