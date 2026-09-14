from core.hunt.sidecar_session import get_sidecar_manager


def test_hunt_report_sections():
    mgr = get_sidecar_manager()
    sess = mgr.start('sess_test','tenantA', window_hours=3, model_enabled=False)
    rep = mgr.report('sess_test')
    assert rep and 'report_markdown' in rep
    markdown = rep['report_markdown']
    assert '# Hunt Session Report' in markdown
    for key in ['session_id','estimate_units','actual_units']:
        assert key in rep['report']
