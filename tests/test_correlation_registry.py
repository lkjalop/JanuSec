import time
from src.core.correlation.rules.registry import CORRELATION_RULES, set_fired_counter_for_tests


class DummyCounter:
    def __init__(self):
        self.counts = {}
    def labels(self, **kw):
        key = kw.get('rule')
        class L:
            def __init__(self, parent, key):
                self.parent = parent
                self.key = key
            def inc(self):
                self.parent.counts[self.key] = self.parent.counts.get(self.key, 0) + 1
        return L(self, key)


def test_rule_registry_fires_and_counter_increments():
    # inject deterministic counter
    dc = DummyCounter()
    set_fired_counter_for_tests(dc)

    # create a synthetic event that matches several exemplar rules
    ev = {
        'protocol': 'ssh',
        'dst_port': 2223,
        'failed_login_count': 6,
        'user_agent': 'curl/7.68.0',
        'ja3_fingerprint': 'rare-abc',
        'domain': 'example.xyz',
        'process': 'certutil.exe',
        'dst_ip': '10.1.1.5',
        'src_ip': '10.0.0.7',
        'scan_rate': 60.0,
        'http_bytes_out': 2000000,
        'last_seen': time.time() - 90000
    }

    fired = CORRELATION_RULES.evaluate(ev)
    assert isinstance(fired, list)
    # Expect at least 4 rules from the exemplar set to fire for comprehensive synthetic event
    assert len(fired) >= 4
    # ensure the counter captured increments for fired rules
    for r in fired:
        assert dc.counts.get(r.name, 0) >= 1
