"""Unittest adapter for pytest-style tests.

This allows environments that only run unittest discovery to execute the
existing function-based tests without rewriting them.
"""
import importlib
import inspect
import tempfile
import unittest
from pathlib import Path

MODULE_NAMES = [
    'tests.test_alert_search',
    'tests.test_dedup_ttl',
    'tests.test_evidence_rotation',
    'tests.test_decay_invariants',
    'tests.test_integrity_chain',
    'tests.test_rule_generic_counter',
]

def _load_module(name):
    try:
        return importlib.import_module(name)
    except Exception as e:  # pragma: no cover
        raise RuntimeError(f"Failed importing {name}: {e}")

def _collect_functions(mod):
    funcs = []
    for name, obj in inspect.getmembers(mod):
        if name.startswith('test_') and callable(obj):
            funcs.append((name, obj))
    return funcs

def _build_kwargs(func):
    kwargs = {}
    resources = []
    for param in inspect.signature(func).parameters.values():
        if param.name == 'tmp_path':
            tmp = tempfile.TemporaryDirectory()
            resources.append(tmp)
            kwargs[param.name] = Path(tmp.name)
        else:
            raise RuntimeError(
                f"Unsupported fixture parameter '{param.name}' in {func.__module__}.{func.__name__}"
            )
    return kwargs, resources

# Dynamically create a TestCase subclass with one method per function
class PyTestFunctionAdapter(unittest.TestCase):
    pass

for mod_name in MODULE_NAMES:
    mod = _load_module(mod_name)
    for fname, func in _collect_functions(mod):
        def _make_test(f):
            def _inner(self):
                kwargs, resources = _build_kwargs(f)
                try:
                    f(**kwargs)
                finally:
                    for resource in resources:
                        resource.cleanup()
            _inner.__name__ = f"test__{mod_name.replace('.', '_')}__{f.__name__}"
            return _inner
        setattr(PyTestFunctionAdapter, f"test_{mod_name.replace('.', '_')}_{fname}", _make_test(func))

if __name__ == '__main__':  # manual fallback
    unittest.main(verbosity=2)
