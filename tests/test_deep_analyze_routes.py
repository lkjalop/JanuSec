import pytest
from src.api.app import create_app


def test_deep_analyze_endpoints_present():
    app = create_app()
    paths = {r.path for r in app.router.routes}
    assert '/api/v1/assessments/deep_analyze' in paths
    assert '/api/v1/assessments/report/{report_id}' in paths
    assert '/api/v1/assessments/csv/deep_analyze/stream' in paths
