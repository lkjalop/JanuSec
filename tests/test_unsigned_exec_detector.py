import time
from src.core.detectors.unsigned_exec_detector import check_and_emit


def test_unsigned_exec_emits():
    # Simulate a simple hopgraph with add_node_factor
    class HG:
        def __init__(self):
            self.factors = {}

        def add_node_factor(self, node, factor):
            self.factors.setdefault(node, []).append(factor)

    hg = HG()
    node = 'endpoint:host-1'
    # blank signed and with hash -> should emit
    emitted = check_and_emit(hg, node, signed=None, file_hash='deadbeef')
    assert emitted is True
    assert 'endpoint:unsigned_exec' in hg.factors.get(node, [])