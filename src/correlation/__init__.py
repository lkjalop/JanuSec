"""Correlation package: canonical event schema, parsers, factor extraction, kill chain reconstruction."""
"""Correlation package public exports and pipeline manifest."""

# Ordered pipeline stages for introspection / diagnostics
CORRELATION_PIPELINE = [
	'temporal',
	'cooccurrence',
	'campaign',
	'suppression',
	'sequence',  # (planned)
	'ml'         # (planned future ML ranking stage)
]

__all__ = ['CORRELATION_PIPELINE']
"""Correlation package (temporal, co-occurrence, dispatcher)."""

from .dispatcher import correlate  # re-export primary entrypoint

__all__ = ['correlate']
