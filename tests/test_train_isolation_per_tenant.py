from __future__ import annotations
import importlib
import sys
from pathlib import Path
import types


def make_fake_graph():
    class FakeG:
        def __init__(self):
            # identity -> deque-like list of events
            self._recent_edges = {
                'tenantA:user1': [{'dst_host': 'h1'} for _ in range(50)],
                'tenantA:user2': [{'dst_host': 'h2'} for _ in range(30)],
                'tenantB:user3': [{'dst_host': 'h3'} for _ in range(5)],
            }
    return FakeG()


def test_per_tenant_export_and_train(tmp_path, monkeypatch):
    # monkeypatch global graph
    fake = make_fake_graph()
    mod = importlib.import_module('scripts.train_isolation')
    importlib.reload(mod)
    # override G and GLOBAL_ISO_MODEL to a dummy
    mod.G = fake
    class DummyModel:
        def __init__(self, model_path=None):
            self.enabled = True
            self._path = model_path
        def fit_partial(self, X, persist=True, path=None):
            # write a small marker file to indicate training was called
            p = Path(path or self._path or 'data/iso_models/dummy.pkl')
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('trained')
        def score(self, x):
            return 0.0
    # monkeypatch IsolationWrapper in the isolation_model module so that instantiation in the script uses DummyModel
    iso_mod = importlib.import_module('src.ml.isolation_model')
    importlib.reload(iso_mod)
    monkeypatch.setattr(iso_mod, 'IsolationWrapper', DummyModel)
    # Run per-tenant-train in-process with controlled argv
    monkeypatch.setenv('ISO_MODELS_DIR', str(tmp_path / 'iso_models'))
    import sys
    monkeypatch.setattr(sys, 'argv', ['train_isolation.py', '--per-tenant-train', '--min-samples', '2'])
    mod.main()
    # check models dir for tenantA model file
    models_dir = Path(str(tmp_path / 'iso_models'))
    assert (models_dir / 'tenantA.pkl').exists()