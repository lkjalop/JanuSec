from src.api.deep_analyze_endpoints import _summarize_ewma_and_hotspots


def test_summarize_ewma_empty():
    assert _summarize_ewma_and_hotspots(None, None) == ''


def test_summarize_ewma_large_matrix():
    # simulate a large list-format matrix of tuples [a,b,value]
    mat = [[f'col{i}', f'col{j}', float(i*j%100)/100.0] for i in range(1,40) for j in range(1,3)]
    summ = _summarize_ewma_and_hotspots({'correlation': mat}, None, max_chars=500)
    assert isinstance(summ, str)
    # should contain 'Top overlap hotspots' when entries present
    assert 'Top overlap hotspots' in summ or 'Hotspot notes' in summ


def test_summarize_ewma_hotspots_dict():
    summ = _summarize_ewma_and_hotspots(None, {'overlap_hotspots': {'a': {'score': 0.9}, 'b': {'score': 0.4}}}, max_chars=300)
    assert 'Hotspot' in summ or 'Hotspot notes' in summ
