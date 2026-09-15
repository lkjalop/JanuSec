from src.core.detectors.identity_role_burst import check_and_emit


def test_identity_role_burst():
    class HG:
        def __init__(self):
            self.f = {}
        def add_node_factor(self, node, factor):
            self.f.setdefault(node, []).append(factor)

    hg = HG()
    principal = 'bob@example.com'
    # Simulate rapid role changes
    for _ in range(3):
        check_and_emit(hg, principal)
    assert 'identity:role_mutation_burst' in hg.f.get(f'identity:{principal}', [])
