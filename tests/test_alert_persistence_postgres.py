import src.api.alerts_endpoints as alerts


def test_alert_postgres_persistence_uses_db_execute(monkeypatch):
    captured = {}

    async def fake_execute(query, *args):
        captured["query"] = query
        captured["args"] = args
        return "OK 1"

    monkeypatch.setenv("APP_DB_DSN", "postgresql://user:pass@db:5432/janusec")
    monkeypatch.setattr("src.db.database.execute", fake_execute, raising=False)

    alert = {
        "id": "alert-1",
        "tenant_id": "tenant-a",
        "title": "Suspicious PowerShell",
        "host": "wkstn-01",
        "user": "alice",
        "verdict": "malicious",
        "confidence": 0.9,
        "factors": [{"factor": "powershell_encoded"}],
        "ts": 1234567890,
    }

    alerts._persist_postgres(alert)

    assert "INSERT INTO alerts" in captured["query"]
    assert captured["args"][1] == "malicious"
    assert captured["args"][2] == 0.9
    assert captured["args"][-1] == "tenant-a"
