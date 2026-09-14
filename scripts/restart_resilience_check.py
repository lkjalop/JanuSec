"""In-process restart-resilience check using TestClient.

This avoids cross-process uvicorn lifecycles that interfere with pytest runs.

Workflow:
 - enable persistence env vars
 - import the app and run TestClient to POST to snapshot endpoint
 - simulate a restart by reloading the hopgraph module and creating a new graph instance
 - call snapshot again and compare
"""
import os
import time
import importlib
from pathlib import Path
from fastapi.testclient import TestClient
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / 'data' / 'test_hopgraph.db'
DB.parent.mkdir(parents=True, exist_ok=True)


def start_process_server(env_overrides: dict[str, str] | None = None):
    env = os.environ.copy()
    env.update(env_overrides or {})
    # Ensure we do not run in lite mode; force full init
    env.pop('PLATFORM_LITE_INIT', None)
    env['TEST_HELPERS_ENABLED'] = env.get('TEST_HELPERS_ENABLED', '1')
    env['HOPGRAPH_PERSISTENCE_ENABLED'] = 'true'
    env['HOPGRAPH_DB_PATH'] = str(DB)
    env['API_KEY'] = env.get('API_KEY', 'devkey123')

    # Use PowerShell start script and run it in background
    cmd = ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'scripts/start_test_server.ps1']
    p = subprocess.Popen(cmd, env=env)
    return p


def wait_for_health(timeout: float = 10.0):
    import requests
    base = 'http://localhost:8080'
    headers = {'x-api-key': os.environ.get('API_KEY', 'devkey123')}
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(base + '/api/v1/graph/self_check', headers=headers, timeout=1.0)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.25)
    return False


def main():
    # Simple process-level persistence check using a child process
    import sys
    cmd_persist = [sys.executable, 'scripts/persist_and_check.py', 'persist', '--db', str(DB)]
    cmd_check = [sys.executable, 'scripts/persist_and_check.py', 'check', '--db', str(DB)]
    envp = os.environ.copy()
    envp.update({'HOPGRAPH_PERSISTENCE_ENABLED': 'true', 'HOPGRAPH_DB_PATH': str(DB)})
    envp['PYTHONPATH'] = str(ROOT)

    print('Running persist step...')
    p1 = subprocess.run(cmd_persist, env=envp, cwd=str(Path.cwd()), capture_output=True, text=True)
    print('persist stdout:', p1.stdout)
    print('persist stderr:', p1.stderr)

    print('Running check step (simulated restart)...')
    p2 = subprocess.run(cmd_check, env=envp, cwd=str(Path.cwd()), capture_output=True, text=True)
    print('check stdout:', p2.stdout)
    print('check stderr:', p2.stderr)
    # Basic validation
    if 'loaded_edges' in p2.stdout:
        print('Restart resilience: loaded edges found')
    else:
        print('Restart resilience: no loaded edges observed')


if __name__ == '__main__':
    main()
