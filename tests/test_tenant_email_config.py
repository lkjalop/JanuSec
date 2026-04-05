import os
from src.integrations.tenant_config import load_email_config

def test_load_email_config_env_overrides(monkeypatch):
    monkeypatch.setenv('EMAIL_VIP_NAMES', 'ceo,cfo,Jane Doe')
    monkeypatch.setenv('EMAIL_CORPORATE_DOMAINS', 'acme.com,corp.acme.com')
    monkeypatch.setenv('GMAIL_POLL_INTERVAL', '120')
    monkeypatch.setenv('O365_POLL_INTERVAL', '180')
    cfg = load_email_config()
    assert 'vip_names' in cfg and any(v.lower() == 'ceo' for v in cfg['vip_names'])
    assert 'corporate_domains' in cfg and 'acme.com' in cfg['corporate_domains']
    assert cfg['poll']['gmail'] == 120
    assert cfg['poll']['o365'] == 180
