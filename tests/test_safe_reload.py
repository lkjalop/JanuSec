import importlib
import sys
import types


def test_safe_reload_normalizes_aliases():
    # Create a fake module object with a spec-like name 'src.api.fake_mod'
    mod = types.ModuleType('src.api.fake_mod')
    # Give it a fake __spec__ with a name attribute to simulate importlib modules
    class Spec: pass
    spec = Spec()
    spec.name = 'src.api.fake_mod'
    mod.__spec__ = spec

    # Ensure only the long name exists in sys.modules
    sys.modules.pop('src.api.fake_mod', None)
    sys.modules.pop('api.fake_mod', None)
    sys.modules['src.api.fake_mod'] = mod

    # Import the helper and call safe_reload on the module object
    from tests.utils.safe_reload import safe_reload

    reloaded = safe_reload(mod)
    # After safe_reload, the short alias should exist and map to the same object
    assert sys.modules.get('api.fake_mod') is sys.modules.get('src.api.fake_mod')
    assert sys.modules.get('api.fake_mod') is mod
    # safe_reload returns a module (may be same instance or reloaded)
    assert reloaded is not None
