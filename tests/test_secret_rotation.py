import os
import time
from src.integrations.secret_rotation import rotate_tenant_secret
from src.integrations.tenant_store import TenantStore


def test_rotate_tenant_secret(monkeypatch, tmp_path):
    monkeypatch.setenv('SECRET_BACKEND', 'memory')
    ts = TenantStore()
    tid = 'rotate-me'
    ts.save_tokens(tid, {'access_token': 'a', 'refresh_token': 'r', 'expires_at': int(time.time())+100})

    def transform(old):
        old['access_token'] = 'rotated'
        return old

    rotate_tenant_secret(tid, transform)
    out = ts.load_tokens(tid)
    assert out['access_token'] == 'rotated'
