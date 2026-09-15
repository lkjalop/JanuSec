import os
from src.core.correlation.rules import registry as reg


def test_registry_contains_batch3_rules():
    """Sanity check: ensure some Batch-3 rule ids are registered at import time.

    This prevents import-order flakiness where tests execute before rule modules
    are imported and decorators run.
    """
    # Load module to be defensive; package init should import weekX, but this
    # makes the check robust in multiple test environments.
    try:
        from src.core.correlation.rules.weekX import expanded_batch  # type: ignore
    except Exception:
        pass

    names = {r.name for r in reg.CORRELATION_RULES.list()}
    # A small set of representative Batch-3 rule ids we expect to be present
    expected = {
        'c2_rare_ja3_beacon',
        'col_browser_data_exfil',
        'pers_wmi_persistence',
    }
    missing = expected - names
    assert not missing, f"Missing expected Batch-3 rules: {missing}"
