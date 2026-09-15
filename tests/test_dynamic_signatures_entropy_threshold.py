import os
from src.signatures.config_store import set_signatures, load_signatures  # type: ignore
from src.graph.reconstruction import path_factors  # type: ignore

def test_dynamic_signature_update(tmp_path, monkeypatch):
    cfg_path = tmp_path / 'sigs.json'
    monkeypatch.setenv('SIGNATURE_CONFIG_PATH', str(cfg_path))
    # initial empty
    cfg = load_signatures()
    assert cfg['process'] == []
    # set new pattern
    set_signatures({'process':[r'evilproc\.exe$'], 'domain':[], 'hash':[]})
    factors = path_factors([{'process':'C:/x/evilproc.exe'}])
    assert 'signature_match' in factors

def test_entropy_threshold_env(monkeypatch):
    monkeypatch.setenv('ENTROPY_HIGH_THRESHOLD','10')  # very high, should suppress factor unless file_hash present
    factors = path_factors([{'process':'C:/Temp/random_name_but_low_entropy.exe'}])
    assert 'high_entropy' not in factors
    # with file hash present it should appear
    factors2 = path_factors([{'file_hash':'abc123', 'process':'aaaaaa'}])
    assert 'high_entropy' in factors2