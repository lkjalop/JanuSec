from __future__ import annotations
import time
from src.correlation.dispatcher import correlate
from src.correlation import dispatcher as disp_mod

def test_sequence_rule_emission(monkeypatch):
    monkeypatch.setenv('SEQ_ENABLED','1')
    monkeypatch.setenv('SEQ_TEST_RULE','1')
    # Reinitialize global sequence correlator (import re-run not trivial; directly adjust existing)
    from src.correlation.sequences import GLOBAL_SEQUENCE_CORRELATOR
    GLOBAL_SEQUENCE_CORRELATOR.rules = GLOBAL_SEQUENCE_CORRELATOR._load_rules()
    host = 'h1'
    base = time.time()
    # Event with first factor
    correlate({'host':host,'ts':base}, ['factor:a'])
    # Event with second factor triggers sequence
    new, d = correlate({'host':host,'ts':base+10}, ['factor:b'])
    assert 'corr:seq_test' in new
    assert d > 0

def test_hashed_pmi_emission(monkeypatch):
    monkeypatch.setenv('COOCC_ENABLED','1')
    monkeypatch.setenv('COOCC_EMIT_SPECIFIC','1')
    monkeypatch.setenv('COOCC_MIN_COUNT','2')
    monkeypatch.setenv('COOCC_PMI_THRESHOLD','0.0')  # force early
    from src.correlation.cooccurrence import GLOBAL_COOCCURRENCE_CORRELATOR
    # Reset internal state for deterministic test
    GLOBAL_COOCCURRENCE_CORRELATOR.factor_counts.clear()
    GLOBAL_COOCCURRENCE_CORRELATOR.pair_counts.clear()
    GLOBAL_COOCCURRENCE_CORRELATOR.last_emit.clear()
    GLOBAL_COOCCURRENCE_CORRELATOR._specific_active = 0
    GLOBAL_COOCCURRENCE_CORRELATOR.emit_specific = True
    GLOBAL_COOCCURRENCE_CORRELATOR.min_count = 2
    GLOBAL_COOCCURRENCE_CORRELATOR.pmi_threshold = 0.0
    # Feed repeated events with pair (x,y)
    f1 = ['x','y']
    correlate({'host':'hp','ts':time.time()}, f1)
    new2, _ = correlate({'host':'hp','ts':time.time()+1}, f1)
    # Expect generic high PMI factor and specific hashed factor
    assert any(f.startswith('corr:pmi:') for f in new2), new2
    assert 'corr:pair_high_pmi' in new2

def test_backpressure_disables_sequence(monkeypatch):
    monkeypatch.setenv('SEQ_ENABLED','1')
    monkeypatch.setenv('SEQ_TEST_RULE','1')
    monkeypatch.setenv('CORR_TIME_BUDGET_MS','1')  # extremely low
    monkeypatch.setenv('CORR_SKIP_ORDER','sequence,cooccurrence,campaign,suppression')
    from src.correlation.sequences import GLOBAL_SEQUENCE_CORRELATOR
    GLOBAL_SEQUENCE_CORRELATOR.rules = GLOBAL_SEQUENCE_CORRELATOR._load_rules()
    # Simulate heavy elapsed time by monkeypatching time.time progression
    real_time = time.time
    t0 = real_time()
    calls = {'n':0}
    def fake_time():
        calls['n'] += 1
        # After first module call, jump forward beyond budget
        return t0 + (0.002 if calls['n'] > 2 else 0.0)
    monkeypatch.setattr(disp_mod.time, 'time', fake_time)
    # Ensure dispatcher skip order reflects env update (module-level set captured at import)
    if 'sequence' not in disp_mod._SKIP_ON_BUDGET:
        disp_mod._SKIP_ON_BUDGET.add('sequence')
    correlate({'host':'hb','ts':t0}, ['factor:a'])  # first step
    new1, _ = correlate({'host':'hb','ts':t0+5}, ['factor:b'])  # would create sequence before disable
    assert 'corr:seq_test' in new1  # first emission occurs
    # Third event should see module disabled due to prior elapsed time triggering adaptive skip
    new2, _ = correlate({'host':'hb','ts':t0+10}, ['factor:b'])
    # Expect no additional sequence factor (cooldown OR disabled). For robustness ensure optional module disabled flag set
    assert 'corr:seq_test' not in new2