from __future__ import annotations
from prometheus_client import Counter, Gauge, Histogram

# embedding queue length (events awaiting vectorization)
EMBED_QUEUE_GAUGE = Gauge('embedding_queue_length', 'Number of events waiting for embedding')

# embedding processing latency
EMBED_LATENCY_HIST = Histogram('embedding_latency_seconds', 'Embedding generation latency seconds', buckets=(0.1,0.5,1,2,5,10))

# mode indicator
EMBED_MODE = Gauge('embedding_mode', 'Embedding mode in use: 0=fallback(hash), 1=model')

def set_queue_length(n: int):
    EMBED_QUEUE_GAUGE.set(n)

def observe_latency(sec: float):
    EMBED_LATENCY_HIST.observe(sec)

def set_mode_fallback():
    EMBED_MODE.set(0)

def set_mode_model():
    EMBED_MODE.set(1)

__all__ = ['set_queue_length','observe_latency','set_mode_fallback','set_mode_model']
