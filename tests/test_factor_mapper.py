from src.core.factor_mapper import score_candidates_from_event


def test_mapper_prefers_sha256_and_user():
    event = {'sha256': 'abcd', 'user': 'alice'}
    ranked = score_candidates_from_event(event)
    assert ranked
    # ensure at least one endpoint-related factor present
    assert any(f.startswith('endpoint:') or f.startswith('identity:') for f, s in ranked)
