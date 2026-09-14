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
from src.api.deep_analyze.enrichment import (  # noqa: F401
    _TS_FIELDS, _DESC_FIELDS, _ACCOUNT_FIELDS, _HOST_FIELDS, _IP_FIELDS, _RESOURCE_FIELDS,
    _EMAIL_RE, _IP_RE, _MITRE_RE, _SEV_RANK, _LOW_VALUE_ACCOUNT_PIVOTS,
    _ACCOUNT_NESTED_PATHS, _HOST_NESTED_PATHS, _IP_NESTED_PATHS,
    _VENDOR_EGRESS_PREFIXES,
    _flatten_row_payload, _safe_identity_text, _is_low_value_account_pivot,
    _extract_first_value, _parse_backend_timestamp, _is_private_ip_text,
    _extract_from_typed_array, _account_fallback_text,
    _extract_accounts_backend, _extract_hosts_backend, _extract_ips_backend,
    _extract_resources_backend, _extract_tags_backend,
    _classify_backend_severity, _severity_label_for_rows,
    _infer_cloud_provider, _infer_plane, _extract_cloud_context,
    _extract_identity_context, _extract_network_context,
    _extract_policy_change_context, _extract_guest_onboarding_context,
    _extract_security_posture_context, _extract_event_context,
    _build_bitemporal_trace, _extract_evidence_mode, _extract_freshness,
    _normalize_assessment_rows, _is_vendor_egress_ip, _is_ioc_confirmed,
    _extract_attacker_ips,
)
from src.api.deep_analyze.cluster_builder import (  # noqa: F401
    _CLUSTER_BUCKET_CAP, _build_remediation_simulation,
    _build_cluster_lead_description, _build_cluster_reason_summary,
    _build_enrichment_guided_cases, _build_inverted_index,
    _build_pair_reason, _build_correlation_clusters, _build_task_entry,
)
