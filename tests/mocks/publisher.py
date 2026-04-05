"""CI/dev-time mocks for Redis/Kafka used by publisher tests."""
class DummyRedis:
    def __init__(self, *a, **k):
        pass
    def publish(self, ch, payload):
        # pretend to publish
        return True


def from_url(dsn):
    return DummyRedis()


class DummyKafkaProducer:
    def __init__(self, *a, **k):
        pass
    def send(self, topic, payload):
        return True
    def flush(self, timeout=None):
        return True
*** End Patch