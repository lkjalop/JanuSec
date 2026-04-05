from __future__ import annotations
import os
import json
from typing import Any


def _publish_redis(payload: dict[str, Any], dsn: str) -> bool:
    try:
        import redis
        r = redis.from_url(dsn)
        r.publish('metrics.events', json.dumps(payload))
        return True
    except Exception:
        return False


def _publish_kafka(payload: dict[str, Any], brokers: str) -> bool:
    try:
        from kafka import KafkaProducer
        p = KafkaProducer(bootstrap_servers=brokers.split(','), value_serializer=lambda v: json.dumps(v).encode('utf-8'))
        p.send('metrics.events', payload)
        p.flush(timeout=5)
        return True
    except Exception:
        return False


def emit_metric_event(name: str, labels: dict[str, str], value: int = 1) -> bool:
    """Best-effort publish of a metric event to Redis or Kafka when configured.

    Uses env vars: `METRICS_PUBLISH_REDIS` or `METRICS_PUBLISH_KAFKA` (comma-separated brokers).
    Returns True when publish likely succeeded, False otherwise.
    """
    enabled = os.getenv('METRICS_PUBLISH_ENABLED', '0')
    if enabled.lower() in ('0','false','no',''):
        return False
    payload = {'metric': name, 'labels': labels, 'value': value}
    rdsn = os.getenv('METRICS_PUBLISH_REDIS')
    if rdsn:
        ok = _publish_redis(payload, rdsn)
        if ok:
            return True
    kb = os.getenv('METRICS_PUBLISH_KAFKA')
    if kb:
        ok = _publish_kafka(payload, kb)
        if ok:
            return True
    return False


__all__ = ['emit_metric_event']
