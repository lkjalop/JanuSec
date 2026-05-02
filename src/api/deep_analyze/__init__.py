"""deep_analyze sub-package.

Re-exports all public symbols so that existing callers of
``src.api.deep_analyze_endpoints`` continue to work unchanged.
Populated incrementally as modules are extracted (Phase A-1 through A-3).
"""
from src.api.deep_analyze.helpers import (  # noqa: F401
    _safe_text,
    _nested_get,
    _collect_strings_from_row,
)
