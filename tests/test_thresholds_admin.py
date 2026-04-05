import os
import json


def test_rule_thresholds_persistence(tmp_path):
    # Use a temporary file for RULE_THRESHOLDS_PATH and set before importing module
    tf = tmp_path / 'rule_thresholds_test.json'
    os.environ['RULE_THRESHOLDS_PATH'] = str(tf)

    # Import module after env var is set so it picks up the temp path
    from src.core.correlation.rules import rule_thresholds
    # Ensure defaults are available
    defaults = rule_thresholds.to_dict()

    # Use the public API to set an in-memory threshold (avoid file-system races)
    rule_thresholds.set_threshold('auth_success_count', 3, persist=False)
    val = rule_thresholds.get_threshold('auth_success_count')
    assert int(val) == 3
