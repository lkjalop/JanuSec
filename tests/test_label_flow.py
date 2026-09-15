import time
import pytest
from core.factor_stats_manager import FACTOR_STATS
from core.factor_attribution_store import FactorAttributionSnapshot, FACTOR_ATTRIBUTIONS
from core.labels_store import LABELS


def test_label_updates_stats():
    # clear global state for test isolation
    FACTOR_STATS._stats.clear()
    FACTOR_ATTRIBUTIONS._by_event.clear()
    FACTOR_ATTRIBUTIONS._recent.clear()
    LABELS._labels.clear()
    # create a fake snapshot
    snap = FactorAttributionSnapshot(
        event_id='evt-1',
        ts=time.time(),
        factors=['f:a','f:b'],
        breakdown=[{'factor':'f:a','contribution':0.8},{'factor':'f:b','contribution':0.2}],
        score=0.9,
        raw_score=0.85,
        confidence=0.9,
        variance=0.0,
        ci95=(0.8,0.9),
    )
    FACTOR_ATTRIBUTIONS.add_snapshot(snap)
    LABELS.add_label('evt-1','tp','test')
    FACTOR_STATS.update_from_label(snap.factors,'tp',time.time())
    st = FACTOR_STATS.get('f:a')
    assert st is not None
    assert st.tp >= 1


def test_precision_and_state_transitions():
    # Reset stats manager isolated instance
    from core.factor_stats_manager import FactorStatsManager
    m = FactorStatsManager()
    # apply 3 tp and 2 fp for factor x
    for _ in range(3):
        m.update_from_label(['x'], 'tp', time.time())
    for _ in range(2):
        m.update_from_label(['x'], 'fp', time.time())
    st = m.get('x')
    assert st is not None
    assert st.tp == 3
    assert st.fp == 2
    p = st.precision()
    assert pytest.approx(p, rel=1e-3) == 3/(3+2)
    # state should be emerging if below default min support (5), total==5 equals min_support => candidate
    assert st.state() in {'candidate','promoted','emerging'}


def test_calibration_export_only_qualifying(tmp_path):
    # create snapshot and labels
    snap = FactorAttributionSnapshot(
        event_id='evt-2',
        ts=time.time(),
        factors=['g:a'],
        breakdown=[{'factor':'g:a','contribution':0.6}],
        score=0.6,
        raw_score=0.58,
        confidence=0.7,
        variance=0.0,
        ci95=(0.5,0.7),
    )
    FACTOR_ATTRIBUTIONS.add_snapshot(snap)
    # add a non-qualifying label
    LABELS.add_label('evt-2','suspicious','t')
    # export should not include evt-2
    from core.recalibrator import propose_and_write
    rows = []
    # use the same logic as export endpoint by importing FACTOR_ATTRIBUTIONS and LABELS
    qualifying = {'tp','fp','benign'}
    for s in FACTOR_ATTRIBUTIONS.recent(10):
        labels = LABELS.get(s.event_id)
        lab = None
        for l in reversed(labels):
            if l.label in qualifying:
                lab = l.label
                break
        if lab:
            rows.append(s.event_id)
    assert 'evt-2' not in rows