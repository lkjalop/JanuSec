import os
import time
import subprocess
import requests
import json
import pytest

# This integration test starts a local Vault dev server and exercises the
# VaultSecretBackend in TenantStore. It's gated by the env var
# RUN_VAULT_INTEGRATION=1 so it doesn't run during normal unit-test runs.

@pytest.mark.skipif(os.getenv('RUN_VAULT_INTEGRATION','0') not in ('1','true','yes'), reason='Vault integration tests disabled')
def test_vault_backend_end_to_end(tmp_path):
    # Start Vault dev server (vault must be installed in PATH for CI runner)
    vault_addr = 'http://127.0.0.1:8200'
    env = os.environ.copy()
    env['VAULT_ADDR'] = vault_addr
    # Launch Vault dev in background
    proc = subprocess.Popen(['vault', 'server', '-dev', '-dev-root-token-id=root'], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        # Wait for Vault to be ready
        for _ in range(20):
            try:
                r = requests.get(f"{vault_addr}/v1/sys/health", timeout=1)
                if r.status_code in (200, 429):
                    break
            except Exception:
                pass
            time.sleep(0.2)
        # Configure env for TenantStore
        os.environ['VAULT_ADDR'] = vault_addr
        os.environ['VAULT_TOKEN'] = 'root'
        os.environ['SECRET_BACKEND'] = 'vault'
        # Import TenantStore lazily now that env is set
        from src.integrations.tenant_store import TenantStore
        store = TenantStore()
        tid = 'test-tenant-vault'
        payload = {'access_token': 'at-1', 'refresh_token': 'rt-1', 'expires_at': int(time.time()) + 3600}
        store.save_tokens(tid, payload)
        loaded = store.load_tokens(tid)
        assert loaded is not None
        assert loaded.get('access_token') == 'at-1'
        # Delete and ensure removed
        store.delete_tokens(tid)
        assert store.load_tokens(tid) is None
    finally:
        try:
            proc.terminate()
        except Exception:
            pass

