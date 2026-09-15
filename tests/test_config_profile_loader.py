import os
from src.config.profile_loader import load_profile, apply_profile

def test_load_profile_dev():
    prof = load_profile('dev')
    assert 'SESSION_CLEAN_INTERVAL_SECONDS' in prof
    assert prof['LOG_LEVEL'] == 'debug'

def test_apply_profile_does_not_override_env(monkeypatch):
    monkeypatch.setenv('SESSION_CLEAN_INTERVAL_SECONDS', '999')
    prof = apply_profile('dev')
    # ensure existing env not overridden
    assert os.getenv('SESSION_CLEAN_INTERVAL_SECONDS') == '999'
    # new key applied
    assert os.getenv('FILE_HASH_HISTORY_MAXLEN') == prof['FILE_HASH_HISTORY_MAXLEN']

def test_apply_profile_then_override_env(monkeypatch):
    apply_profile('demo')
    # override after apply should reflect new value
    monkeypatch.setenv('FILE_HASH_HISTORY_MAXLEN', '1234')
    assert os.getenv('FILE_HASH_HISTORY_MAXLEN') == '1234'
