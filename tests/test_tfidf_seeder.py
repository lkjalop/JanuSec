import os
import json
import pytest

from src.enrichment.tfidf import seed_corpus_from_observations, MODEL_PATH


def load_observations():
    try:
        from src.crq import fair_shadow as _fsmod
        inst = getattr(_fsmod, '_PERSIST_INSTANCE', None)
        if inst is not None:
            data = inst.read_all()
            if data:
                return data
            # seed a small sample for deterministic tfidf seeding
            # seed several deterministic samples so training set won't be empty
            sample = []
            for i in range(5):
                sample.append({'hash': ('%02x' % i) * 16, 'expected_loss': 2000.0 + i * 10, 'dread_inputs': {'damage': i % 3 + 1, 'exploitability': (i+1) % 3 + 1}, 'meta': {}})
            try:
                for s in sample:
                    inst.persist(s)
                return inst.read_all()
            except Exception:
                return sample
    except Exception:
        pass
    p = os.path.join('data', 'crq_shadow.json')
    if not os.path.exists(p):
        pytest.skip('no crq_shadow.json present; skip seeder')
    with open(p, 'r', encoding='utf-8') as f:
        return json.load(f)


def test_tfidf_seeder_runs():
    obs = load_observations()
    # ensure we have at least one observation with dread_inputs or meta
    useful = [o for o in obs if (o.get('dread_inputs') or o.get('meta'))]
    if not useful:
        # fallback to deterministic sample
        obs = [{'hash': 'ff'*16, 'expected_loss': 2000.0, 'dread_inputs': {'damage': 1, 'exploitability': 1}, 'meta': {}}]
    seed_corpus_from_observations(obs)
    # model file should exist in some form
    assert MODEL_PATH.exists()
