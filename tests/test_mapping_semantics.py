from src.core.scoring.mapping_semantics import compute_mapping_semantics

def test_mapping_semantics_basic():
    factors = [{'factor':'mapping_semantics_rich','score':0.6}]
    mapping_stats = {'user':'u','host':'h','file_hash':'f'}
    score = compute_mapping_semantics(factors, mapping_stats, ['user','host','file_hash','domain','process'])
    assert 0.0 <= score <= 1.0
