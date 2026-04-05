import json

from src.core.quality.factor_quality import FactorQualityManager


def test_reload_calibration_config(tmp_path, monkeypatch):
    monkeypatch.setenv('FACTOR_QUALITY_STATE_PATH', str(tmp_path / 'state.json'))
    mgr = FactorQualityManager()
    cfg_path = tmp_path / 'cal.json'
    cfg_path.write_text(json.dumps({
        'context_multipliers': {'identity:vip': 1.75},
        'observations': {'endpoint:vss_deletion': {'tp': 5, 'fp': 1}},
    }))
    assert mgr.reload_calibration_config(str(cfg_path))
    ctx = mgr.get_context_multipliers()
    assert ctx['identity:vip'] == 1.75
    assert mgr.tp['endpoint:vss_deletion'] >= 5
    assert mgr.calibration_path() == str(cfg_path)


def test_apply_calibration_dict_inline(monkeypatch):
    monkeypatch.setenv('FACTOR_QUALITY_STATE_PATH', 'data/tmp_state.json')
    mgr = FactorQualityManager()
    mgr.apply_calibration_dict({
        'context_multipliers': {'endpoint:svc': 1.2},
        'observations': {'net:beacon': {'tp': 3, 'fp': 0}},
    })
    assert mgr.get_context_multipliers()['endpoint:svc'] == 1.2
    assert mgr.tp['net:beacon'] >= 3
