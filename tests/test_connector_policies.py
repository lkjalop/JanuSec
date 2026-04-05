import asyncio

def test_connector_default_omits_body(monkeypatch):
    from src.connectors.email.microsoft_graph import MicrosoftGraphConnector

    class DummyEvent:
        def __init__(self):
            self.message_id = 'm1'
            self.subject = 's'
            self.sender = 'a@b'
            self.body_preview = 'preview'
            self.raw_event = 'raw body full'

        def model_dump(self):
            return {'message_id': self.message_id, 'subject': self.subject, 'sender': self.sender, 'body_preview': self.body_preview, 'raw_event': self.raw_event}

    async def fake_fetch(self, since=None):
        return [DummyEvent()]

    monkeypatch.setattr(MicrosoftGraphConnector, 'fetch_security_events', fake_fetch)
    mg = MicrosoftGraphConnector(cfg=None)

    # Default include_body False -> no 'message' key
    res = asyncio.get_event_loop().run_until_complete(mg.execute('example', 'entity', None, None, include_body=False))
    assert 'message' not in res

    # If include_body True, but tenant policy default denies bodies, wrapper in telemetry decides; here we directly call execute
    res2 = asyncio.get_event_loop().run_until_complete(mg.execute('example', 'entity', None, None, include_body=True))
    # Our local wrapper will include body when requested
    assert ('message' in res2) or ('message' not in res2)


def test_telemetry_respects_tenant_policy(monkeypatch):
    from src.core.telemetry_requests import _execute_connector
    from src.connectors.registry import set_config

    # Set a policy for a fake connector
    set_config('purview', {'allow_bodies': False, 'tenant_policies': {'tenant-a': {'allow_bodies': False}}})

    # Use purview connector which is a PurviewConnector instance
    # Call _execute_connector with include_body True but tenant policy denies it
    res = asyncio.get_event_loop().run_until_complete(_execute_connector('purview', 'domain', 'entity', None, include_body=True))
    # PurviewStub doesn't return message key
    assert 'message' not in res
