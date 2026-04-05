import os
import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_CONNECTOR_CONTRACTS", "0") not in ("1", "true", "yes"),
    reason="Set RUN_CONNECTOR_CONTRACTS=1 to run connector contract tests",
)

# Placeholder: once connectors are hardened, add contract tests for Splunk/Sentinel/CrowdStrike.
# Examples:
# - test_splunk_fetch_pagination_contract()
# - test_sentinel_auth_refresh_and_checkpoint()
# - test_crowdstrike_rate_limit_and_resume()
