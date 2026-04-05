import os
os.environ['PLATFORM_LITE_INIT'] = '1'
os.environ['TEST_HELPERS_ENABLED'] = '1'

import pytest
raise SystemExit(pytest.main(['-q','tests/test_webhook_callbacks.py']))
