def test_mapping_tags_atlas_and_owasp_llm():
    # Factors chosen to trigger specific tags
    factors = ['tool_abuse', 'sensitive_output_leak']
    # Prefer the helper that the server will call
    try:
        from src.analysis.explain_mapping import map_factors_to_tags  # type: ignore
        tags = map_factors_to_tags(factors)
    except Exception:
        # Fallback directly to mapping table if helper is unavailable
        from src.core.mappings.factor_to_mitre import get_all_mappings  # type: ignore
        tags = get_all_mappings(factors)

    atlas = set(tags.get('atlas') or [])
    owasp = set(tags.get('owasp_llm') or [])
    # Validate ATLAS includes Model Spec Violation for tool_abuse
    assert any('Model Spec Violation' in a for a in atlas), f"ATLAS tags missing Model Spec Violation: {atlas}"
    # Validate OWASP LLM05 shows up for sensitive_output_leak
    assert any(t.startswith('LLM05:') or 'LLM05' in t for t in owasp), f"OWASP LLM tags missing LLM05: {owasp}"

