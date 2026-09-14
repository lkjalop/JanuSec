import asyncio
import os
import tempfile
from src.ml.closed_loop_manager import ClosedLoopManager


def test_closed_loop_basic_flow(tmp_path):
    dbf = tmp_path / 'cl.db'
    mgr = ClosedLoopManager(db_path=str(dbf))
    # Add synthetic feedback
    for i in range(120):
        evt = f'evt-{i}'
        mgr.add_feedback(evt, ['endpoint:lolbin_misuse', 'net:beacon_detected'], 1)

    assert mgr.ready_to_learn()
    cand = asyncio.get_event_loop().run_until_complete(mgr.propose_weights())
    assert isinstance(cand, dict) and 'endpoint:lolbin_misuse' in cand
    cands = mgr.list_candidates()
    assert len(cands) >= 1
    # Approve first candidate
    applied = mgr.approve_candidate(int(cands[0]['id']), actor='tester', current_weights={'endpoint:lolbin_misuse': 0.5, 'net:beacon_detected': 0.5})
    assert 'endpoint:lolbin_misuse' in applied
