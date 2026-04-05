import os
import sys
os.environ['INCIDENTS_DEBUG']='1'
os.environ['PLATFORM_LITE_INIT']='1'
os.environ['TEST_HELPERS_ENABLED']='1'
import pytest
sys.exit(pytest.main(['-q','-s','tests/test_graph_endpoints.py::test_graph_reconstruct_attach_creates_incident']))
