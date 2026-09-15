from src.graph.multi_root_merge import simple_multi_merge


def test_simple_multi_merge():
    # build a small synthetic graph via neighbor function
    graph = {
        'a': ['b','c'],
        'b': ['d'],
        'c': ['d','e'],
        'd': [],
        'e': []
    }
    def nbrs(n):
        return graph.get(n, [])
    res = simple_multi_merge(nbrs, ['a','c'], max_depth=2)
    assert res['visited_count'] >= 4
    assert 'a' in res['roots']
    assert 'c' in res['roots']
    # origin_map should contain lists for provided roots
    assert set(res['origin_map'].keys()) == {'a','c'}
