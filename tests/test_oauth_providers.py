import asyncio
import time
import os

from src.integrations.auth.msal_provider import MSALProvider
from src.integrations.auth.google_oauth_provider import GoogleOAuthProvider
from src.integrations.msal_mock import MSALMock


def test_msal_provider_url():
    p = MSALProvider('cid', 'secret', tenant='contoso', redirect_uri='https://app/cb')
    url = p.get_authorization_url(state='s')
    assert 'client_id=cid' in url
    assert 'redirect_uri=' in url


def test_google_provider_url():
    p = GoogleOAuthProvider('gcid', 'gsecret', redirect_uri='https://app/cb')
    url = p.get_authorization_url(state='s')
    assert 'client_id=gcid' in url
    assert 'prompt=consent' in url


# Note: full network interactions not executed in unit tests; functions should not crash

def test_msal_refresh_no_tokens():
    p = MSALProvider('cid', 'secret')
    assert p.refresh('nonexistent') is None


def test_google_refresh_no_tokens():
    p = GoogleOAuthProvider('gcid', 'gsecret')
    assert p.refresh('nonexistent') is None
