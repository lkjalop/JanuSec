import os
import sys
os.environ['FAST_TEST_MODE'] = '1'
os.environ['PLATFORM_LITE_INIT'] = '1'
os.environ['DISABLE_DB'] = '1'

import pytest

args = sys.argv[1:] or ['tests/test_incremental_rerank.py', 'tests/test_redis_llm_queue_unit.py', 'tests/test_redis_dequeue_integration.py']
rc = pytest.main(args)
sys.exit(rc)
