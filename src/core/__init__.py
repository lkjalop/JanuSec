"""Core package init for src.core.

This file is intentionally minimal. Package-level symbols are defined
in submodules (e.g. src.core.idempotency) and should be imported directly.
"""
try:
	# Prefer the tested clean implementation if available.
	from .arc_redis_queue_impl import enqueue_job, pop_job, ack_job, get_redis_client
except Exception:
	enqueue_job = pop_job = ack_job = get_redis_client = None

__all__ = ['enqueue_job', 'pop_job', 'ack_job', 'get_redis_client']

# Runtime shim: if the impl module is available, ensure imports of
# `src.core.arc_redis_queue` resolve to it (works around a corrupted
# on-disk arc_redis_queue.py during repair).
try:
	import sys, importlib
	impl = importlib.import_module('src.core.arc_redis_queue_impl')
	sys.modules.setdefault('src.core.arc_redis_queue', impl)
except Exception:
	pass
