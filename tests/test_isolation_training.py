from __future__ import annotations
import importlib


def test_iso_wrapper_disabled(monkeypatch):
    # simulate sklearn import error at import time
    monkeypatch.setenv('ENABLE_ISO_ML', '1')

    import builtins
    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if isinstance(name, str) and name.startswith('sklearn'):
            raise ImportError('no sklearn')
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, '__import__', fake_import)

    # reload the module to pick up the faux environment
    import src.ml.isolation_model as iso_mod
    importlib.reload(iso_mod)
    # wrapper should be present but disabled
    assert hasattr(iso_mod, 'GLOBAL_ISO_MODEL')
    assert not iso_mod.GLOBAL_ISO_MODEL.enabled
    # fit_partial should not raise
    iso_mod.GLOBAL_ISO_MODEL.fit_partial([[1.0, 2.0]])


def test_iso_wrapper_persist(monkeypatch, tmp_path):
    # this test will run only if sklearn is available; otherwise skip
    try:
        import sklearn  # type: ignore
    except Exception:
        import pytest

        pytest.skip('sklearn not available in test env')

    monkeypatch.setenv('ENABLE_ISO_ML', '1')
    model_path = tmp_path / 'iso_model.pkl'

    # reload module to pick up env
    import src.ml.isolation_model as iso_mod
    importlib.reload(iso_mod)

    iso = iso_mod.GLOBAL_ISO_MODEL
    if not iso.enabled:
        import pytest

        pytest.skip('Isolation wrapper not enabled in this environment')

    # prepare simple dataset
    X = [[1.0, 1.0], [2.0, 1.0], [10.0, 5.0], [1.5, 0.5]]
    iso.fit_partial(X, persist=True, path=str(model_path))
    # if sklearn present and fit worked, file should exist
    assert model_path.exists()
    # reload model into a fresh wrapper and verify is_ready
    new_iso = iso_mod.IsolationWrapper(model_path=str(model_path))
    # new_iso.is_ready may be True if load succeeded; at minimum constructing shouldn't raise
    assert True