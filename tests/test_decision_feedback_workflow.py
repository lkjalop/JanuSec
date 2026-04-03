from fastapi.testclient import TestClient

from src.api.app import app


client = TestClient(app)


def test_decision_feedback_persists_workflow_in_evidence(monkeypatch):
    captured = {}

    async def _fake_insert_label(event_id, decision_id, label, tenant_id, test_id=None, variant=None, evidence=None, query_template=None):
        captured["event_id"] = event_id
        captured["decision_id"] = decision_id
        captured["label"] = label
        captured["tenant_id"] = tenant_id
        captured["evidence"] = evidence
        captured["query_template"] = query_template
        return None

    import src.repositories.decision_labels_repo as repo

    monkeypatch.setattr(repo, "insert_label", _fake_insert_label)

    resp = client.post(
        "/api/v1/feedback/decision",
        json={
            "decision_id": "dec-workflow-1",
            "label": "true_positive",
            "factors": ["privilege"],
            "evidence": "Analyst reached the user.",
            "workflow": {
                "user_contacted": True,
                "change_ticket_found": True,
                "owner_confirmed": False,
                "change_ticket": "CHG-5678",
            },
        },
        headers={"x-api-key": "devkey123"},
    )

    assert resp.status_code == 200, resp.text
    assert '"workflow"' in (captured.get("evidence") or "")
    assert '"CHG-5678"' in (captured.get("evidence") or "")
