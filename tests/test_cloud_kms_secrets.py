from src.core.detectors.cloud_kms_secrets import record_access


def test_cloud_kms_secrets_spike():
    class HG:
        def __init__(self):
            self.f = {}
        def add_node_factor(self, node, factor):
            self.f.setdefault(node, []).append(factor)

    hg = HG()
    principal = 'alice@example.com'
    # Simulate many accesses in short window
    for _ in range(12):
        record_access(hg, principal)
    # Expect at least one emission (implementation uses baseline heuristic)
    assert 'cloud:kms_secrets_access_anomaly' in hg.f.get(f'identity:{principal}', [])
