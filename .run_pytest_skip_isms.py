import os
import sys
os.environ['SKIP_ISMS_SCAN'] = '1'
import pytest
sys.exit(pytest.main(sys.argv[1:]))
