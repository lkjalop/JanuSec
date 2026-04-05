import os
import sys
os.environ['TEST_DEBUG'] = '1'
os.environ['PYTHONNOUSERSITE'] = '1'
import pytest
sys.exit(pytest.main(sys.argv[1:]))
