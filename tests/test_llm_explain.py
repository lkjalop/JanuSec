from fastapi.testclient import TestClient
from src.api.app import create_app
import src.analysis.cost_tracker as cost_tracker


def test_llm_explain_includes_llm_and_records_cost(monkeypatch):
    app = create_app()
    client = TestClient(app)

    # Mock summarize_row to return predictable structure
    def _mock_summarize_row(row, ctx):
        return {
            'text': 'Deep analysis summary',
            'model': 'mock-model',
            'meta': {'input_tokens': 10, 'output_tokens': 40, 'estimated_cost': 0.005},
            'payload': {'structured': True}
        }

    # Replace the LLMAssessmentClient class used by the endpoint with a dummy that returns our mock
    class DummyLLM:
        def summarize_row(self, row, ctx):
            return _mock_summarize_row(row, ctx)

    monkeypatch.setattr('src.api.llm_endpoints.LLMAssessmentClient', DummyLLM)

    # Clear cost tracker recent entries
    cost_tracker.EXTERNAL_TRACKER.recent.clear()

    payload = {
        'factor_synthesis': {'final_score': 0.8},
        'mapping_semantics': {},
        'domain_diversity': {},
        'hopgraph_context': {},
        'row': {'process_name': 'evil.exe', 'host': 'host1', 'user': 'u1'}
    }

    r = client.post('/api/v1/llm/explain', json=payload)
    assert r.status_code == 200
    data = r.json()
    assert 'llm' in data
    llm = data['llm']
    assert llm.get('model') == 'mock-model'
    # Cost should have been recorded in tracker recent entries
    recents = cost_tracker.EXTERNAL_TRACKER.recent
    assert any(r.get('model') == 'mock-model' and r.get('cost') == 0.005 for r in recents)
