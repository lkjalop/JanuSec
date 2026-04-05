import os, json, time
from src.config import risk_loader

def test_risk_config_load_and_hash(tmp_path):
    # backup env
    cfg_path = tmp_path / 'risk_config.json'
    data = {
        "version": 1,
        "weights": {"lateral": 0.31, "priv_escalation": 0.5, "cloud_pivot":0.25, "new_host":0.25, "high_value_touch":0.3},
        "thresholds": {"suspicious":0.55, "threat":1.25, "decay_half_life_seconds":800},
        "ewma": {"alpha":0.2, "warmup_min":10, "residual_scale":0.4},
        "rarity": {"min_samples":20, "idf_smoothing":1.0}
    }
    with open(cfg_path,'w',encoding='utf-8') as f:
        json.dump(data,f)
    os.environ['RISK_CONFIG_PATH'] = str(cfg_path)
    c1 = risk_loader.load_config(force=True)
    h1 = risk_loader.config_hash()
    # modify
    time.sleep(0.01)
    data['weights']['lateral'] = 0.4
    with open(cfg_path,'w',encoding='utf-8') as f:
        json.dump(data,f)
    c2 = risk_loader.load_config(force=True)
    h2 = risk_loader.config_hash()
    assert c1['weights']['lateral'] != c2['weights']['lateral']
    assert h1 != h2

def test_risk_config_invalid_reverts(tmp_path):
    cfg_path = tmp_path / 'risk_config.json'
    good = {
        "version": 1,
        "weights": {"lateral": 0.3, "priv_escalation": 0.5, "cloud_pivot":0.25, "new_host":0.25, "high_value_touch":0.3},
        "thresholds": {"suspicious":0.5, "threat":1.2, "decay_half_life_seconds":900}
    }
    with open(cfg_path,'w',encoding='utf-8') as f:
        json.dump(good,f)
    os.environ['RISK_CONFIG_PATH'] = str(cfg_path)
    risk_loader.load_config(force=True)
    h_good = risk_loader.config_hash()
    # write invalid (negative weight)
    bad = good.copy()
    bad['weights'] = {"lateral": -1}
    with open(cfg_path,'w',encoding='utf-8') as f:
        json.dump(bad,f)
    # Should keep old config
    cfg_after = risk_loader.load_config(force=True)
    assert cfg_after['weights']['lateral'] == good['weights']['lateral']
    assert risk_loader.config_hash() == h_good
