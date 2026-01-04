from scripts import drain_writeback_dlq


def test_attempt_repost_success(monkeypatch, tmp_path):
    item = {'base_url': 'https://example', 'api_key': 'k', 'tenant_id': 't', 'events': [{'a':1}]}

    class FakeResp:
        def read(self):
            return b'ok'

    def fake_urlopen(req, timeout=10):
        return FakeResp()

    monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)
    res = drain_writeback_dlq.attempt_repost(item)
    assert res is True
