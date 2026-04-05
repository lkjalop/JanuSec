import os
import time
from core.factor_attribution_store import FactorAttributionSnapshot, FACTOR_ATTRIBUTIONS
from core.labels_store import LABELS
from core.recalibrator import propose_and_write, mark_proposal, PROPOSAL_HISTORY
from repositories import calibration_proposals_repo as repo


def test_repo_persists_accepted_proposal_fields(tmp_path):
    # Isolate DB to a temp file
    db_path = tmp_path / 'calibration_proposals.sqlite'
    os.environ['CALIBRATION_PROPOSALS_DB'] = str(db_path)

    # Prepare labeled snapshots
    # Clear in-memory stores to avoid cross-test contamination
    try:
        FACTOR_ATTRIBUTIONS._by_event.clear()
        FACTOR_ATTRIBUTIONS._recent.clear()
    except Exception:
        pass
    try:
        PROPOSAL_HISTORY.clear()
    except Exception:
        pass
    try:
        LABELS._labels.clear()
    except Exception:
        pass
    now = time.time()
    for i in range(60):
        eid = f'repo-{i}'
        snap = FactorAttributionSnapshot(
            event_id=eid,
            ts=now + i,
            factors=['rf1','rf2'] if i % 2 == 0 else ['rf3'],
            breakdown=[{'factor':'rf1','contribution':0.55}],
            score=0.55,
            raw_score=0.52,
            confidence=0.9,
            variance=0.0,
            ci95=(0.45, 0.65)
        )
        FACTOR_ATTRIBUTIONS.add_snapshot(snap)
        LABELS.add_label(eid, 'tp' if i % 2 == 0 else 'fp', 'test')

    # Propose and accept
    p = propose_and_write(limit=500)
    assert p is not None
    ts = float(p['ts'])
    ok = mark_proposal(ts, accept=True)
    assert ok

    # Read back from repo
    rows = repo.list_proposals(limit=5)
    assert isinstance(rows, list)
    assert len(rows) >= 1
    row = rows[0]

    # Validate required fields
    assert 'k' in row and isinstance(row['k'], float)
    assert 'x0' in row and isinstance(row['x0'], float)
    assert 'loglik' in row and isinstance(row['loglik'], float)
    assert 'accepted' in row and row['accepted'] is True
    assert 'samples' in row and row['samples'] > 0
    # Validate analytics fields
    assert 'ks_tp_fp' in row and (row['ks_tp_fp'] is None or isinstance(row['ks_tp_fp'], float))
    assert 'tp_factor_counts' in row and isinstance(row['tp_factor_counts'], dict)
    assert 'fp_factor_counts' in row and isinstance(row['fp_factor_counts'], dict)
    # Ensure factor count blobs are parseable and non-empty
    # (At least one factor should be present given our data)
    total_tp = sum(row['tp_factor_counts'].values()) if row['tp_factor_counts'] else 0
    total_fp = sum(row['fp_factor_counts'].values()) if row['fp_factor_counts'] else 0
    assert (total_tp + total_fp) > 0
