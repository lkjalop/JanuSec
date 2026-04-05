"""Core enrichment helpers (lightweight demo exports).

This package intentionally exposes only the smallest surface required by
importing modules during tests. A richer ENRICHMENT object is provided by the
main `src.enrichment` package; here we export a minimal placeholder so late
imports (e.g., src.api.server) succeed in lite/test modes.
"""
from .dkim_history import get_last_dkim, record_dkim_result

# Minimal runtime ENRICHMENT placeholder used by some modules during import-time
# (tests may replace this by importing src.enrichment.* when needed).
ENRICHMENT = {
	'get_last_dkim': get_last_dkim,
	'record_dkim_result': record_dkim_result,
}

__all__ = ['get_last_dkim', 'record_dkim_result', 'ENRICHMENT']
