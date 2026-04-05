import os
import time

from src.correlation.suppression import SuppressionCorrelator
from src.feedback.store import GLOBAL_FEEDBACK_STORE


def _seed_feedback(factors, classification='fp', count=5):
    # Create multiple feedback records to give factors low quality (fp heavy)
    for i in range(count):
        fac_objs = [{'name': f} for f in factors]
        GLOBAL_FEEDBACK_STORE.upsert(event_id=f'evt-{classification}-{factors[0]}-{i}', verdict=classification, factors=fac_objs, decision_meta={'confidence':0.5,'verdict':'SUSPICIOUS'})
    GLOBAL_FEEDBACK_STORE.recompute_quality()


def test_suppression_adaptive_low_quality_pair_triggers_early():
    # Configure environment BEFORE creating correlator instance
    os.environ['SUPPRESSION_ENABLED'] = '1'
    os.environ['SUPPRESS_MIN_SUPPORT'] = '6'  # default
    os.environ['SUPPRESSION_FEEDBACK_ADAPT'] = '1'
    os.environ['FEEDBACK_LOW_QUALITY_THRESH'] = '0.45'

    # Seed low-quality factors (fp only -> low Laplace precision)
    f1, f2 = 'test:lowq:A', 'test:lowq:B'
    _seed_feedback([f1, f2], classification='fp', count=5)  # score ~ 1/(5+2)=0.142

    corr = SuppressionCorrelator()

    emitted_total = []
    # Generate 3 FP events containing both factors; support=3 (< min_support=6) but >= relaxed 3
    for i in range(3):
        new_factors, delta = corr.ingest({'event_id': f'e{i}'}, [f1, f2], had_tp=False, had_fp=True)
        emitted_total.extend(new_factors)
        if 'corr:suppress_low_value' in new_factors:
            break
    assert 'corr:suppress_low_value' in emitted_total, 'Adaptive suppression did not trigger early for low-quality pair'


def test_suppression_no_adapt_requires_full_support():
    # Reset environment to disable adaptation
    os.environ['SUPPRESSION_ENABLED'] = '1'
    os.environ['SUPPRESS_MIN_SUPPORT'] = '6'
    os.environ['SUPPRESSION_FEEDBACK_ADAPT'] = '0'
    # use distinct factors to avoid reusing earlier stats
    f1, f2 = 'test:noadapt:A', 'test:noadapt:B'
    _seed_feedback([f1, f2], classification='fp', count=5)
    corr = SuppressionCorrelator()

    emitted_total = []
    for i in range(3):  # support=3 < min_support=6
        new_factors, delta = corr.ingest({'event_id': f'x{i}'}, [f1, f2], had_tp=False, had_fp=True)
        emitted_total.extend(new_factors)
    assert 'corr:suppress_low_value' not in emitted_total, 'Suppression should not trigger before min_support when adaptation disabled'

    # Continue until reaching support >=6
    for i in range(3,7):
        new_factors, delta = corr.ingest({'event_id': f'x{i}'}, [f1, f2], had_tp=False, had_fp=True)
        if 'corr:suppress_low_value' in new_factors:
            break
    assert 'corr:suppress_low_value' in corr.ingest({'event_id': 'x7'}, [f1, f2], had_tp=False, had_fp=True)[0] or 'corr:suppress_low_value' in new_factors