import os
import json
from fastapi.testclient import TestClient
from src.api.app import create_app, app


client = TestClient(app)


def test_msgraph_callback_client_state_reject(monkeypatch):
    monkeypatch.setenv('MSGRAPH_CLIENT_STATE', 'expected-state')
    payload = {'value': [{'clientState': 'bad-state', 'id': '1'}]}
    resp = client.post('/api/v1/subscriptions/msgraph/callback', json=payload)
    assert resp.status_code == 403


def test_msgraph_callback_accept(monkeypatch):
    monkeypatch.setenv('MSGRAPH_CLIENT_STATE', 'expected-state')
    payload = {'value': [{'clientState': 'expected-state', 'id': '1'}]}
    resp = client.post('/api/v1/subscriptions/msgraph/callback', json=payload)
    assert resp.status_code == 200


def test_gmail_callback_verification_reject(monkeypatch):
    monkeypatch.setenv('GMAIL_PUBSUB_VERIFICATION_TOKEN', 'token123')
    payload = {'message': {'attributes': {'verification_token': 'bad'}}}
    resp = client.post('/api/v1/subscriptions/gmail/callback', json=payload)
    assert resp.status_code == 403


def test_gmail_callback_accept(monkeypatch):
    monkeypatch.setenv('GMAIL_PUBSUB_VERIFICATION_TOKEN', 'token123')
    payload = {'message': {'attributes': {'verification_token': 'token123'}}}
    resp = client.post('/api/v1/subscriptions/gmail/callback', json=payload)
    assert resp.status_code == 200
