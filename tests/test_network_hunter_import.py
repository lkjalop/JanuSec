def test_network_hunter_import_sanity():
    # Simple import test to catch indentation / syntax issues early
    import importlib
    mod = importlib.import_module('src.modules.network_hunter')
    assert hasattr(mod, 'NetworkThreatHunter')
