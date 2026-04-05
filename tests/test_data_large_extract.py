from src.core.detectors.data_large_extract import check_and_emit


def test_data_large_extract_detects():
    class HG:
        def __init__(self):
            self.f = {}
        def add_node_factor(self, node, factor):
            self.f.setdefault(node, []).append(factor)

    hg = HG()
    node = 'ip:1.2.3.4'
    # Prime the EWMA with a few normal values
    for v in (1000, 1200, 900, 1100):
        check_and_emit(hg, node, v)
    # Large event should trigger (use larger value to exceed dynamic threshold)
    emitted = check_and_emit(hg, node, 20_000_000)
    assert emitted is True
    assert 'data:large_extract' in hg.f.get(node, [])
