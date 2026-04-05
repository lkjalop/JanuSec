import os
import importlib

from src.ml.feature_registry import FeatureRegistry, FeatureSpec


def test_register_and_get(tmp_path, monkeypatch):
    reg = FeatureRegistry()
    spec = FeatureSpec('test_feat', 'numeric', 'last', 60, 0.0, 'test')
    reg.register(spec)
    assert reg.get('test_feat') == spec
    assert any(f.name == 'test_feat' for f in reg.all())


def test_enabled_include_exclude(monkeypatch):
    reg = FeatureRegistry()
    a = FeatureSpec('a', 'numeric', 'last', 60)
    b = FeatureSpec('b', 'numeric', 'last', 60)
    c = FeatureSpec('c', 'numeric', 'last', 60)
    reg.register(a); reg.register(b); reg.register(c)

    # No env: all present
    monkeypatch.delenv('FEATURE_INCLUDE', raising=False)
    monkeypatch.delenv('FEATURE_EXCLUDE', raising=False)
    names = {f.name for f in reg.enabled()}
    assert names >= {'a','b','c'}

    # Include only b
    monkeypatch.setenv('FEATURE_INCLUDE', 'b')
    names = {f.name for f in reg.enabled()}
    assert names == {'b'}

    # Exclude c
    monkeypatch.delenv('FEATURE_INCLUDE', raising=False)
    monkeypatch.setenv('FEATURE_EXCLUDE', 'c')
    names = {f.name for f in reg.enabled()}
    assert 'c' not in names
