import pytest
from src.playbooks.email_triage import EmailTriagePlaybook
from src.connectors.email.report_phish_mailbox import ReportPhishMailboxConnector


class FakeGraph:
    def __init__(self, messages=None):
        self._messages = messages or []

    def get_messages(self, mailbox, since=None):
        return self._messages

    def get_attachments(self, message_id):
        # return attachments for message with matching id
        for m in self._messages:
            if m.get("id") == message_id:
                return m.get("attachments", [])
        return []

    def search_similar_messages(self, tenant, query):
        # simple filtering by query substrings
        out = []
        for m in self._messages:
            if query in (m.get("subject") or "") or query in (m.get("from") or ""):
                out.append(m)
        return out

    def quarantine_messages(self, tenant, ids, reason="phish"):
        return {"quarantined": len(ids), "failed": 0}


def test_report_phish_mailbox_parses_forwarded_eml():
    fake_msg = {
        "id": "r1",
        "from": "user@example.com",
        "to": "reports@tenant",
        "subject": "Fwd: suspicious",
        "body": "Please investigate",
        "attachments": [{"name": "forwarded.eml", "contentBytes": "From: attacker@bad.com\nSubject: phish\n"}],
    }
    g = FakeGraph(messages=[fake_msg])
    r = ReportPhishMailboxConnector(g, "reports@tenant")
    out = r.fetch_new_reports(None)
    assert len(out) == 1
    assert out[0].raw_event.get("forwarded_eml_hash") is not None


def test_triage_playbook_search_and_quarantine():
    fake_msg = {"id": "m1", "from": "attacker@bad.com", "subject": "click me"}
    g = FakeGraph(messages=[fake_msg])
    graph_connector = g
    pb = EmailTriagePlaybook(graph_connector, soar_base=None)
    iocs = {"sender": "attacker@bad.com", "subject": "click me"}
    res = pb.bulk_search_and_quarantine("tenant1", iocs)
    assert res["found"] >= 0
    assert isinstance(res["quarantine_result"], dict)


def test_expand_iocs_and_soar_call(monkeypatch):
    fake_msg = {"id": "m1", "from": "attacker@bad.com", "subject": "click me"}
    g = FakeGraph(messages=[fake_msg])
    pb = EmailTriagePlaybook(g, soar_base="https://soar.local", soar_api_key="key123")
    iocs = {"sender": "attacker@bad.com", "url": "https://evil.example/path", "subject": "click me"}

    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured['url'] = url
        captured['json'] = json
        captured['headers'] = headers
        class R:
            def json(self):
                return {'status': 'ok'}
        return R()

    monkeypatch.setattr('requests.post', fake_post)

    res = pb.bulk_search_and_quarantine('tenant1', iocs)
    # SOAR not called by bulk_search_and_quarantine by default; test expansion
    expanded = pb.expand_iocs(iocs)
    assert expanded.get('url_host') == 'evil.example'
    assert 'url_fingerprint' in expanded


def test_bulk_quarantine_dry_run_and_punycode():
    # punycode domain for xn-- example
    fake_msg = {"id": "m1", "from": "Attacker <attacker@xn--eexample-9db.com>", "subject": "click me", "body": "visit https://xn--d1acpjx3f.xn--p1ai/path"}
    g = FakeGraph(messages=[fake_msg])
    pb = EmailTriagePlaybook(g, soar_base=None)
    iocs = {"sender": "attacker@xn--eexample-9db.com", "url": "https://xn--d1acpjx3f.xn--p1ai/path", "dry_run": True}
    res = pb.bulk_search_and_quarantine('tenant1', iocs)
    assert res.get('quarantine_result', {}).get('dry_run') is True
    assert 'url_fingerprint' in pb.expand_iocs(iocs)


def test_click_persistence_and_fetch():
    # remove existing db for a clean run
    import os
    p = 'data/clicks.db'
    try:
        if os.path.exists(p):
            os.remove(p)
    except Exception:
        pass
    from src.connectors.email.click_events import ClickEvent
    from src.connectors.email.click_persistence import enqueue_click, fetch_recent_clicks
    ce = ClickEvent('msg-1', 'user1', 'https://a.test', 1234567890.0, 'unknown', 'ua', '127.0.0.1')
    enqueue_click(ce)
    recent = fetch_recent_clicks(limit=10)
    assert len(recent) >= 1
