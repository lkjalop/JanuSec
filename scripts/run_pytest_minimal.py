"""Run pytest on a single test file with a clean env to avoid app import side-effects."""
import os
import sys
import pytest

# Unset env vars that pytest.ini forces which cause app imports at collection
for k in ['PLATFORM_LITE_INIT', 'DISABLE_DB', 'FAST_TEST_MODE', 'TEST_HELPERS_ENABLED']:
    os.environ.pop(k, None)

# pass through args
args = sys.argv[1:] or ['tests/test_import_moto.py', '-q']
print('Running pytest with args:', args)
rc = pytest.main(args)
sys.exit(rc)
