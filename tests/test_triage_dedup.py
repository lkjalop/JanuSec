import pytest
from src.core.correlation.triage_dedup import bucket_by_hash, mini_batch_k_medoids


def test_bucket_by_hash_groups_similar():
    rows = [
        {'user': 'alice', 'sha256': 'a'*64, 'host': 'h1'},
        {'user': 'alice', 'sha256': 'a'*64, 'host': 'h2'},
        {'user': 'bob', 'sha256': 'b'*64, 'host': 'h2'},
    ]
    buckets = bucket_by_hash(rows, ['user', 'sha256'], bucket_bits=8)
    # Expect at least 2 buckets and both alice rows bucket together
    found = False
    for b, br in buckets.items():
        users = {r['user'] for r in br}
        if 'alice' in users and len(br) >= 2:
            found = True
    assert found, 'alice rows should be bucketed together'


def test_mini_batch_k_medoids_basic():
    rows = [
        {'user': 'alice', 'sha256': 'a'*64, 'host': 'h1'},
        {'user': 'alice', 'sha256': 'a'*64, 'host': 'h3'},
        {'user': 'bob', 'sha256': 'b'*64, 'host': 'h2'},
        {'user': 'charlie', 'sha256': 'c'*64, 'host': 'h4'},
    ]
    medoids, assignments = mini_batch_k_medoids(rows, k=2, random_state=1)
    assert len(medoids) == 2
    assert len(assignments) == len(rows)
    # Ensure similar 'alice' rows share an assignment
    alice_idxs = [i for i, r in enumerate(rows) if r['user']=='alice']
    assert assignments[alice_idxs[0]] == assignments[alice_idxs[1]]
