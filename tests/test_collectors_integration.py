import os
import pytest
from unittest.mock import patch, MagicMock
from src.collectors.iam_okta_adapter import OktaIAMCollector
from src.collectors.iam_aad_adapter import AzureADCollector
from src.collectors.cloud_aws_config_adapter import AWSConfigCollector
from src.collectors.cloud_gcp_asset_adapter import GCPAssetCollector
from src.collectors.email_o365_adapter import O365EmailCollector
from src.collectors.email_gmail_adapter import GmailEmailCollector

def test_okta_collector_success(monkeypatch):
    os.environ['OKTA_API_TOKEN'] = 'dummy'
    os.environ['OKTA_ORG_URL'] = 'https://dummy.okta.com'
    with patch('src.collectors.iam_okta_adapter.requests.get') as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"id": "okta-1"}]
        mock_resp.headers = {'link': ''}
        mock_get.return_value = mock_resp
        collector = OktaIAMCollector()
        events = collector.fetch_events(0)
        assert events and events[0]['id'] == 'okta-1'

def test_okta_collector_error(monkeypatch):
    os.environ['OKTA_API_TOKEN'] = 'dummy'
    os.environ['OKTA_ORG_URL'] = 'https://dummy.okta.com'
    with patch('src.collectors.iam_okta_adapter.requests.get') as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = 'error'
        mock_get.return_value = mock_resp
        collector = OktaIAMCollector()
        events = collector.fetch_events(0)
        assert events == []

def test_aad_collector_success(monkeypatch):
    os.environ['AAD_TENANT_ID'] = 'tenant'
    os.environ['AAD_CLIENT_ID'] = 'client'
    os.environ['AAD_CLIENT_SECRET'] = 'secret'
    with patch('src.collectors.iam_aad_adapter.msal.ConfidentialClientApplication') as mock_app, \
         patch('src.collectors.iam_aad_adapter.requests.Session') as mock_session:
        mock_app.return_value.acquire_token_for_client.return_value = {'access_token': 'token'}
        mock_sess = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'value': [{"id": "aad-1"}]}
        mock_resp.headers = {}
        mock_sess.get.return_value = mock_resp
        mock_session.return_value = mock_sess
        collector = AzureADCollector()
        events = collector.fetch_events(0)
        assert events and events[0]['id'] == 'aad-1'

def test_aad_collector_error(monkeypatch):
    os.environ['AAD_TENANT_ID'] = 'tenant'
    os.environ['AAD_CLIENT_ID'] = 'client'
    os.environ['AAD_CLIENT_SECRET'] = 'secret'
    with patch('src.collectors.iam_aad_adapter.msal.ConfidentialClientApplication') as mock_app, \
         patch('src.collectors.iam_aad_adapter.requests.Session') as mock_session:
        mock_app.return_value.acquire_token_for_client.return_value = {}
        mock_sess = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = 'error'
        mock_sess.get.return_value = mock_resp
        mock_session.return_value = mock_sess
        collector = AzureADCollector()
        events = collector.fetch_events(0)
        assert events == []

def test_aws_collector_success(monkeypatch):
    os.environ['AWS_ACCESS_KEY_ID'] = 'key'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'secret'
    with patch('src.collectors.cloud_aws_config_adapter.boto3.client') as mock_client:
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {'configurationItems': [{"resourceId": "aws-1", "configurationItemCaptureTime": MagicMock(timestamp=lambda: 1e10)}]}
        ]
        mock_client.return_value.get_paginator.return_value = paginator
        collector = AWSConfigCollector()
        events = collector.fetch_events(0)
        assert events and events[0]['resourceId'] == 'aws-1'

def test_aws_collector_error(monkeypatch):
    os.environ['AWS_ACCESS_KEY_ID'] = 'key'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'secret'
    with patch('src.collectors.cloud_aws_config_adapter.boto3.client') as mock_client:
        mock_client.side_effect = Exception('fail')
        collector = AWSConfigCollector()
        events = collector.fetch_events(0)
        assert events == []

def test_gcp_collector_success(monkeypatch):
    os.environ['GCP_CREDENTIALS_JSON'] = 'dummy.json'
    os.environ['GCP_PROJECT_ID'] = 'p123'
    with patch('src.collectors.cloud_gcp_asset_adapter.asset_v1.AssetServiceClient') as mock_client, \
         patch('src.collectors.cloud_gcp_asset_adapter.service_account.Credentials.from_service_account_file') as mock_creds, \
         patch('os.path.exists', return_value=True):
        mock_client.return_value.list_assets.return_value = [MagicMock(_pb={'id': 'gcp-1'})]
        collector = GCPAssetCollector()
        events = collector.fetch_events(0)
        assert events and events[0]['id'] == 'gcp-1'

def test_gcp_collector_error(monkeypatch):
    os.environ['GCP_CREDENTIALS_JSON'] = 'dummy.json'
    os.environ['GCP_PROJECT_ID'] = 'p123'
    with patch('src.collectors.cloud_gcp_asset_adapter.asset_v1.AssetServiceClient') as mock_client, \
         patch('src.collectors.cloud_gcp_asset_adapter.service_account.Credentials.from_service_account_file') as mock_creds, \
         patch('os.path.exists', return_value=True):
        mock_client.side_effect = Exception('fail')
        collector = GCPAssetCollector()
        events = collector.fetch_events(0)
        assert events == []

def test_o365_collector_success(monkeypatch):
    os.environ['O365_TENANT'] = 'tenant'
    os.environ['O365_CLIENT_ID'] = 'client'
    os.environ['O365_CLIENT_SECRET'] = 'secret'
    os.environ['O365_USER_ID'] = 'user'
    with patch('src.collectors.email_o365_adapter.msal.ConfidentialClientApplication') as mock_app, \
         patch('src.collectors.email_o365_adapter.requests.Session') as mock_session, \
         patch('src.collectors.email_o365_adapter.MicrosoftGraphConnector', None):
        mock_app.return_value.acquire_token_for_client.return_value = {'access_token': 'token'}
        mock_sess = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'value': [{"id": "o365-1"}]}
        mock_resp.headers = {}
        mock_sess.get.return_value = mock_resp
        mock_session.return_value = mock_sess
        collector = O365EmailCollector()
        events = collector.fetch_events(0)
        assert events and events[0]['id'] == 'o365-1'

def test_o365_collector_error(monkeypatch):
    os.environ['O365_TENANT'] = 'tenant'
    os.environ['O365_CLIENT_ID'] = 'client'
    os.environ['O365_CLIENT_SECRET'] = 'secret'
    os.environ['O365_USER_ID'] = 'user'
    with patch('src.collectors.email_o365_adapter.msal.ConfidentialClientApplication') as mock_app, \
         patch('src.collectors.email_o365_adapter.requests.Session') as mock_session, \
         patch('src.collectors.email_o365_adapter.MicrosoftGraphConnector', None):
        mock_app.return_value.acquire_token_for_client.return_value = {}
        mock_sess = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = 'error'
        mock_sess.get.return_value = mock_resp
        mock_session.return_value = mock_sess
        collector = O365EmailCollector()
        events = collector.fetch_events(0)
        assert events == []

def test_gmail_collector_success(monkeypatch):
    os.environ['GMAIL_SERVICE_ACCOUNT_JSON'] = 'dummy.json'
    os.environ['GMAIL_USER_ID'] = 'user'
    with patch('src.collectors.email_gmail_adapter.service_account.Credentials.from_service_account_file') as mock_creds, \
         patch('src.collectors.email_gmail_adapter.build') as mock_build, \
         patch('os.path.exists', return_value=True):
        mock_service = MagicMock()
        mock_service.users.return_value.messages.return_value.list.return_value.execute.return_value = {'messages': [{'id': 'gmail-1'}]}
        mock_service.users.return_value.messages.return_value.get.return_value.execute.return_value = {'id': 'gmail-1'}
        mock_build.return_value = mock_service
        collector = GmailEmailCollector()
        events = collector.fetch_events(0)
        assert events and events[0]['id'] == 'gmail-1'

def test_gmail_collector_error(monkeypatch):
    os.environ['GMAIL_SERVICE_ACCOUNT_JSON'] = 'dummy.json'
    os.environ['GMAIL_USER_ID'] = 'user'
    with patch('src.collectors.email_gmail_adapter.service_account.Credentials.from_service_account_file') as mock_creds, \
         patch('src.collectors.email_gmail_adapter.build') as mock_build, \
         patch('os.path.exists', return_value=True):
        mock_build.side_effect = Exception('fail')
        collector = GmailEmailCollector()
        events = collector.fetch_events(0)
        assert events == []
