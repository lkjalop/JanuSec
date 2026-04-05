import importlib
import os


def test_reset_preserves_monkeypatched_enabled(monkeypatch):
    # Ensure test env starts clean
    monkeypatch.delenv('RATE_LIMIT_FORCE_ENABLE', raising=False)
    # Import the module and monkeypatch the module-level flag to True
    mod = importlib.import_module('src.api.app')
    monkeypatch.setattr(mod, '_RATE_LIMIT_ENABLED', True, raising=False)
    # Now call the helper which normally re-evaluates env
    mod.reset_rate_limit_for_tests()
    # The function should preserve the monkeypatched True and not flip it off
    assert getattr(mod, '_RATE_LIMIT_ENABLED', False) is True


def test_reset_respects_force_enable(monkeypatch):
    # Set the FORCE_ENABLE env var before calling the helper
    monkeypatch.setenv('RATE_LIMIT_FORCE_ENABLE', '1')
    # Reload module to ensure any module-level reads would pick up env (helper should also respect it)
    importlib.reload(importlib.import_module('src.api.app'))
    mod = importlib.import_module('src.api.app')
    # Deliberately set module flag to False to verify helper will flip it when force is set
    monkeypatch.setattr(mod, '_RATE_LIMIT_ENABLED', False, raising=False)
    mod.reset_rate_limit_for_tests()
    assert getattr(mod, '_RATE_LIMIT_ENABLED', False) is True


def test_reset_preserves_monkeypatched_disabled(monkeypatch):
    # Ensure helper does not flip an explicit False to True unless forced
    monkeypatch.delenv('RATE_LIMIT_FORCE_ENABLE', raising=False)
    mod = importlib.import_module('src.api.app')
    monkeypatch.setattr(mod, '_RATE_LIMIT_ENABLED', False, raising=False)
    mod.reset_rate_limit_for_tests()
    assert getattr(mod, '_RATE_LIMIT_ENABLED', True) is False
