from core.hunt.provenance import compute_session_hash
from core.hunt.sidecar_session import get_sidecar_manager


def test_provenance_hash_stability():
    mgr = get_sidecar_manager()
    sess = mgr.start('prov1','tenantP', window_hours=3, model_enabled=False)
    h1 = sess.replay_hash
    # recompute with same parameters
    h2 = compute_session_hash(sess.window_hours, sess.model_enabled, sess.tenant, sess.estimate_units)
    assert h1 == h2

def test_replay_endpoint_logic():
    mgr = get_sidecar_manager()
    orig = mgr.start('origA','tenantQ', window_hours=24, model_enabled=True)
    rep = mgr.replay('origA', new_session_id='origA_replay')
    assert rep.report.get('replay_of') == 'origA'
