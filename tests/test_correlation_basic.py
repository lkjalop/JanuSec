from __future__ import annotations
from src.core.correlation.temporal_sequencer import TemporalSequencer
from src.core.correlation.cooccurrence import CoOccurrenceTracker
from src.core.correlation.suppression import SuppressionEngine
from src.core.correlation.metrics_correlation import ensure_corr_metrics
from src.core.correlation.negative_patterns import GLOBAL_NEGATIVE_PATTERNS

def test_temporal_sequence_match():
    seq = TemporalSequencer()
    seq.patterns = [{"name":"demo","sequence":["a","b"],"max_span_seconds":5}]
    seq.record('ent', ['a'])
    seq.record('ent', ['b'])
    matches = seq.detect()
    assert matches and matches[0]['pattern'] == 'demo'

def test_cooccurrence_scoring():
    co = CoOccurrenceTracker()
    co.record(['x','y','z'])
    assert co.score_pair('x','y') >= 1.0

def test_suppression_engine_lower_and_suppress(tmp_path):
    tpl = {
        "templates": [
            {"name":"suppress_test","match_factors":["f1"],"action":"suppress"},
            {"name":"lower_test","match_factors":["f2"],"action":"lower_weight","delta":-0.5}
        ]
    }
    p = tmp_path / 'sup.json'; p.write_text(__import__('json').dumps(tpl))
    se = SuppressionEngine(str(p))
    adj = se.evaluate({}, ['f1','f2','f3'])
    assert adj['f1'] < -500 and adj['f2'] == -0.5

def test_negative_patterns_eval(tmp_path):
    # ensure at least one benign match
    pats = {"patterns":[{"name":"benign","match_factors":["x"],"conditions":{}}]}
    p = tmp_path / 'neg.json'; p.write_text(__import__('json').dumps(pats))
    from src.core.correlation.negative_patterns import NegativePatterns
    np = NegativePatterns(str(p))
    assert np.evaluate(['x','y']) == ['benign']

def test_metrics_registration():
    ensure_corr_metrics()  # should not raise
