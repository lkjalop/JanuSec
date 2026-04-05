$Env:INCIDENTS_DEBUG='1'
$Env:PLATFORM_LITE_INIT='1'
$Env:TEST_HELPERS_ENABLED='1'
python -m pytest -q -s tests/test_graph_endpoints.py::test_graph_reconstruct_attach_creates_incident -k test_graph_reconstruct_attach_creates_incident
