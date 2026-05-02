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
from src.api.deep_analyze.persistence import (  # noqa: F401
    REPORT_STORE,
    PARENT_CHILD_INDEX,
    _persist_assessment_state,
    _get_assessment_cached,
    _write_assessment_index,
    _load_assessment_from_disk,
)
from src.api.deep_analyze.verdict_seed import (  # noqa: F401
    _derive_human_validation_required,
    _VERDICT_HVR_MAP,
    _apply_hvr_gating,
    _initial_cluster_verdict,
)
