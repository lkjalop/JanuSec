import os
from core.metrics.publisher import emit_metric_event


def test_emit_disabled_by_default(monkeypatch):
    monkeypatch.delenv('METRICS_PUBLISH_ENABLED', raising=False)
    assert emit_metric_event('m', {'k':'v'}, 1) is False


def test_emit_redis(monkeypatch, tmp_path):
    monkeypatch.setenv('METRICS_PUBLISH_ENABLED','1')
    monkeypatch.setenv('METRICS_PUBLISH_REDIS','redis://localhost:6379/0')
    # monkeypatch redis.from_url to a dummy publisher
    class Dummy:
        def publish(self, ch, payload):
            assert ch == 'metrics.events'
            assert 'metric' in payload
    def dummy_from_url(dsn):
        return Dummy()
    monkeypatch.setitem(__import__('sys').modules, 'redis', type('m', (), {'from_url': staticmethod(dummy_from_url)}))
    assert emit_metric_event('m', {'k':'v'}, 2) is True


def test_emit_kafka(monkeypatch):
    monkeypatch.setenv('METRICS_PUBLISH_ENABLED','1')
    monkeypatch.setenv('METRICS_PUBLISH_KAFKA','broker1')
    class DummyP:
        def __init__(self,*a,**k):
            pass
        def send(self, topic, payload):
            assert topic == 'metrics.events'
        def flush(self, timeout=None):
            pass
    monkeypatch.setitem(__import__('sys').modules, 'kafka', type('m', (), {'KafkaProducer': DummyP}))
    assert emit_metric_event('m2', {'k2':'v2'}, 1) is True
