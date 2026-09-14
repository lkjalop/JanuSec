"""Controlled local crash, complete encrypted backup and independent restore.

Uses only synthetic Vesper telemetry and canary credentials/checkpoints. The
service must be stopped before invocation. A real provider is not contacted.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

import psutil
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.pilot_state import configure
from src.backup.pilot_state import backup, restore, state_lock


def stop_owned(process):
    try:
        parent = psutil.Process(process.pid)
        children = parent.children(recursive=True)
    except psutil.NoSuchProcess:
        children = []
    for child in children:
        try:
            child.kill()
        except psutil.NoSuchProcess:
            pass
    if process.poll() is None:
        process.kill()
    process.wait(timeout=20)
    psutil.wait_procs(children, timeout=20)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--backup-key', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--port', type=int, default=8443)
    args = parser.parse_args()
    state, output = args.state.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    restored = state.parent / ('restored-' + secrets.token_hex(4))
    archive = state.parent / ('complete-' + secrets.token_hex(4) + '.enc')
    result = {'live_provider': False, 'fixture': 'Vesper', 'mode': 'crash-backup-restore'}
    values = json.loads((state / 'secrets.json').read_text(encoding='utf-8'))
    entry = json.loads(values['API_KEYS_JSON'])[0]
    headers = {'x-api-key': entry['key'], 'x-tenant-id': entry['tenant_id']}
    base = f'https://127.0.0.1:{args.port}'
    children = []
    logs = []

    def launch(root):
        log = (root.parent / (root.name + '-recovery-server.log')).open('wb')
        logs.append(log)
        proc = subprocess.Popen([sys.executable, str(ROOT / 'scripts/pilot_state.py'), 'serve',
                                 '--state', str(root), '--port', str(args.port)],
                                stdout=log, stderr=log,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        children.append(proc)
        session = requests.Session(); session.trust_env = False
        session.verify = str(root / 'tls-cert.pem')
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError('isolated_server_exited: inspect private server log')
            try:
                if session.get(base + '/', timeout=2).status_code == 200:
                    return proc, session
            except requests.RequestException:
                pass
            time.sleep(1)
        raise RuntimeError('isolated_server_start_timeout')

    try:
        proc, session = launch(state)
        # A previous interrupted verification may also be recovering. Finish it
        # before starting the next controlled interruption; never rewrite its status.
        existing = session.get(base + '/api/v1/assessments', headers=headers, timeout=60)
        assert existing.ok
        prior = existing.json()
        prior = prior if isinstance(prior, list) else prior.get('assessments', prior.get('items', []))
        for job in prior:
            if job.get('status') in {'queued', 'running'}:
                prior_id = job.get('assessment_id') or job.get('id')
                deadline = time.monotonic() + 900
                while time.monotonic() < deadline:
                    progress = session.get(base + f'/api/v1/assessments/{prior_id}/progress/poll', headers=headers, timeout=60).json()
                    if progress['status'] not in {'queued', 'running'}:
                        break
                    time.sleep(2)
                assert progress['status'] == 'ready', 'previous_interrupted_job_did_not_recover'
        try:
            backup(state, archive, args.backup_key)
        except RuntimeError as exc:
            assert 'pilot_state_busy' in str(exc)
            result['live_backup_rejected'] = True
        else:
            raise AssertionError('a running state was backed up')
        files = sorted((ROOT / 'tests/fixtures/telemetry_corpora/Vesper').glob('*'))
        files = [p for p in files if p.is_file() and p.suffix != '.md']
        handles = [path.open('rb') for path in files]
        try:
            response = session.post(base + '/api/v1/assessments/upload', headers=headers,
                                    files=[('files', (path.name, handle)) for path, handle in zip(files, handles)], timeout=120)
        finally:
            for handle in handles: handle.close()
        assert response.status_code == 202, response.status_code
        aid = response.json()['assessment_id']
        result['interrupted_assessment'] = aid
        print(json.dumps({'stage': 'interruptible_upload_started', 'assessment_id': aid}), flush=True)
        deadline = time.monotonic() + 240
        peak = 0
        while time.monotonic() < deadline:
            root_process = psutil.Process(proc.pid)
            peak = max(peak, sum(p.memory_info().rss for p in [root_process, *root_process.children(recursive=True)]))
            response = session.get(base + f'/api/v1/assessments/{aid}/progress/poll', headers=headers, timeout=60)
            progress = response.json()
            if progress['status'] == 'running' and progress.get('row_count', 0) > 0:
                result['interrupted_progress'] = progress
                break
            assert progress['status'] not in {'ready', 'failed', 'cancelled'}, 'did_not_observe_interruptible_job'
            time.sleep(0.5)
        else:
            raise RuntimeError('no_interruptible_progress')
        stop_owned(proc)
        result['sampled_peak_process_tree_rss_bytes'] = peak
        session.close()
        # Both the raw files and partially persisted derived rows now exist on disk.
        with state_lock(state):
            configure(state)
            from src.core.ingest import store
            before = store._db().execute('SELECT count(*) FROM normalized_rows WHERE assessment_id=?', [aid]).fetchone()[0]
            assert before > 0
            assert len(store.raw_files_for(aid)) == 4
            store._conn.close(); store._conn = None
            from src.integrations.tenant_store import FileSecretBackend
            from src.integrations.checkpoint_store import CheckpointStore
            from src.core.connectors.checkpoint_store_v2 import CheckpointStoreV2
            canary = secrets.token_urlsafe(32)
            FileSecretBackend().save('pilot-customer/recovery-canary', {'value': canary})
            CheckpointStore().save('recovery-canary', 'cursor-42')
            CheckpointStoreV2().save('recovery-canary', 'stream', {'cursor': 'cursor-43'})
            result['partial_rows_before_crash_recovery'] = before
        result['backup'] = backup(state, archive, args.backup_key)
        result['restore'] = restore(archive, restored, args.backup_key)
        result['restored_state'] = str(restored)
        print(json.dumps({'stage': 'encrypted_backup_restored', 'files': result['restore']['files']}), flush=True)
        # Test keys/checkpoints through a fresh interpreter so module-level paths
        # cannot accidentally read the original state directory.
        probe = [sys.executable, str(ROOT / 'scripts/verify_pilot_state_contents.py'),
                 '--state', str(restored), '--assessment', aid,
                 '--canary-sha256', hashlib.sha256(canary.encode()).hexdigest()]
        checked = subprocess.run(probe, capture_output=True, text=True, timeout=60)
        if checked.returncode:
            raise RuntimeError('restored_state_contents_failed: ' + checked.stderr[-1000:])
        result['restored_contents'] = json.loads(checked.stdout)
        proc, session = launch(restored)
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            response = session.get(base + f'/api/v1/assessments/{aid}/progress/poll', headers=headers, timeout=60)
            assert response.ok, response.status_code
            progress = response.json()
            if progress['status'] in {'ready', 'failed', 'cancelled'}:
                break
            time.sleep(2)
        assert progress['status'] == 'ready', progress.get('error')
        response = session.get(base + f'/api/v1/assessments/{aid}/evidence?limit=1', headers=headers, timeout=60)
        assert response.ok and response.json()['total'] == 98750, 'loss_or_duplicate_rows_after_recovery'
        result['recovered_records'] = response.json()['total']
        verify = subprocess.run([sys.executable, str(ROOT / 'scripts/verify_isolated_pilot.py'),
                                 '--state', str(restored), '--port', str(args.port),
                                 '--reuse', str(args.baseline.resolve()), '--output', str(output / 'after-restore.json')],
                                capture_output=True, text=True, timeout=180)
        if verify.returncode:
            raise RuntimeError('restored_API_verification_failed: ' + verify.stderr[-1500:])
        result['completed_case_and_history_preserved'] = True
        stop_owned(proc)
        checked = subprocess.run(probe + ['--expected-rows', '98750'], capture_output=True, text=True, timeout=60)
        if checked.returncode:
            raise RuntimeError('physical_recovery_verification_failed: ' + checked.stderr[-1000:])
        result['recovered_physical_storage'] = json.loads(checked.stdout)
        result['restored_state'] = str(restored)
        result['passed'] = True
    finally:
        for proc in children:
            if proc.poll() is None:
                stop_owned(proc)
        for log in logs: log.close()
        (output / 'recovery.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
