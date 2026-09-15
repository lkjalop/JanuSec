"""Operate a loopback HTTPS pilot with one writer and complete offline backups.

This is an isolated deployment profile, not a production-readiness certificate.
Use a private operator-owned state directory outside the checkout. No credentials
are printed. The generated localhost certificate is for local verification only.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.backup.pilot_state import backup, restore, state_lock
from src.security.runtime_profile import UNSAFE_FLAGS, validate_live_auth_configuration


def private_write(path: Path, value: bytes):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(value)


def initialize(state: Path, key_file: Path, tenant: str):
    from cryptography import x509
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from src.api.tenant_helpers import validate_tenant_id
    validate_tenant_id(tenant, required=True)
    if any((parent / '.git').exists() for parent in (state, *state.parents, *key_file.parents)):
        raise ValueError('pilot_secrets_must_be_outside_source_checkouts')
    if state.exists() or key_file.exists() or key_file.is_relative_to(state):
        raise ValueError('init_requires_new_state_and_external_backup_key')
    state.mkdir(parents=True, mode=0o700)
    key_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_write(key_file, secrets.token_bytes(32))
    values = {
        'API_KEYS_JSON': json.dumps([{'key': secrets.token_urlsafe(48), 'tenant_id': tenant,
                                    'subject': 'bootstrap-administrator', 'expires_at': int(time.time()) + 7 * 86400,
                                    'scopes': ['*']}]),
        'JWT_SECRET': secrets.token_urlsafe(48), 'JWT_ISSUER': 'janusec-isolated-pilot',
        'JWT_AUDIENCE': 'janusec-isolated-pilot',
        'INTEGRATIONS_ENCRYPTION_KEY': Fernet.generate_key().decode('ascii'),
        'ADMIN_API_KEY': secrets.token_urlsafe(48),
    }
    private_write(state / 'secrets.json', json.dumps(values).encode('utf-8'))
    private_write(state / 'pilot.json', json.dumps({'schema': 1, 'tenant_id': tenant}).encode('utf-8'))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'JanuSec isolated localhost')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=7))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))
    private_write(state / 'tls-key.pem', key.private_bytes(serialization.Encoding.PEM,
                  serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    private_write(state / 'tls-cert.pem', cert.public_bytes(serialization.Encoding.PEM))
    return {'initialized': True, 'tenant_id': tenant, 'certificate': 'localhost-only; expires in 7 days'}


def configure(state: Path):
    if state == ROOT or state.is_relative_to(ROOT):
        raise ValueError('pilot_state_must_be_outside_source_checkout')
    config = json.loads((state / 'pilot.json').read_text(encoding='utf-8'))
    values = json.loads((state / 'secrets.json').read_text(encoding='utf-8'))
    allowed = {'API_KEYS_JSON', 'JWT_SECRET', 'JWT_ISSUER', 'JWT_AUDIENCE',
               'INTEGRATIONS_ENCRYPTION_KEY', 'ADMIN_API_KEY'}
    if set(values) != allowed or any(not isinstance(v, str) or not v for v in values.values()):
        raise ValueError('invalid_pilot_secrets_configuration')
    # Only inherit OS process essentials, never external credentials or state paths.
    essential = {'PATH', 'SYSTEMROOT', 'WINDIR', 'SYSTEMDRIVE', 'USERPROFILE', 'HOME',
                 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP', 'TMPDIR', 'LANG', 'LC_ALL',
                 'PYTHONUTF8', 'PYTHONIOENCODING'}
    inherited = {k: v for k, v in os.environ.items() if k.upper() in essential}
    os.environ.clear()
    os.environ.update(inherited)
    os.environ.update(values)
    os.environ.update({name: '0' for name in UNSAFE_FLAGS})
    os.environ.update({
        'ENV': 'production', 'APP_ENV': 'production', 'JANUSEC_RUNTIME_PROFILE': 'production',
        'STRICT_API_KEY_ENFORCEMENT': '1', 'DEFAULT_FRONTEND': 'console',
        'TENANT_DEFAULT': config['tenant_id'], 'DEFAULT_TENANT': config['tenant_id'],
        'LLM_PROVIDER': 'deterministic', 'LLM_SUMMARIES_ENABLED': '0',
        'LLM_ALLOW_LOCAL_DETERMINISTIC': '1', 'DISABLE_BACKGROUND_TASKS': '1',
        'TEMPORAL_RAG_EMBED': 'off',
        'SKIP_ISMS_SCAN': '1', 'DISABLE_METRICS_AT_IMPORT': '1', 'DB_DISABLE_NETWORK_CONNECT': '1',
        'SESSION_CLEAN_INTERVAL_SECONDS': '0', 'CONNECTOR_AUTOPOLL_ENABLED': '0',
        'JANUSEC_INGEST_QUEUE_MAX': '2', 'JANUSEC_INGEST_JOB_TIMEOUT_S': '600',
        'JANUSEC_MAX_UPLOAD_BYTES': str(64 * 1024 * 1024), 'JANUSEC_MAX_FILES': '12',
        'EVIDENCE_LEDGER_REQUIRED': '1',
        'ALLOWED_ORIGINS': 'https://127.0.0.1', 'LOG_LEVEL': 'WARNING',
    })
    paths = {
        'PLAYBOOKS_DIR': 'data/playbooks', 'CLUSTER_ENRICH_DIR': 'data/cluster_enrich',
        'ARTIFACTS_DIR': 'artifacts', 'ISMS_DB_PATH': 'data/isms_index.db',
        'DISPATCH_AUDIT_DB': 'data/dispatch_audit.db', 'TENANT_QUOTA_DB': 'data/tenant_quotas.db',
        'DB_FALLBACK_PATH': 'data/platform.sqlite', 'JANUSEC_INGEST_DB': 'data/ingest.duckdb',
        'JANUSEC_RAW_DIR': 'data/raw', 'SESSION_PERSIST_DIR': 'data/sessions',
        'ASSESSMENTS_DIR': 'data/sessions', 'EWMA_HISTORY_PATH': 'data/ewma.json',
        'HOPGRAPH_DB_PATH': 'data/hopgraph.db', 'TENANT_STORE_DIR': 'data/tenant_store',
        'TENANT_PERSIST_DIR': 'data/tenants', 'POLLING_STATE_DIR': 'data/polling_state',
        'CONNECTORS_CHECKPOINT_DIR': 'data/checkpoints', 'CONNECTOR_CHECKPOINTS_PATH': 'data/checkpoints/legacy.json',
        'CONNECTOR_CHECKPOINTS_V2_DIR': 'data/checkpoints/v2',
        'JANUSEC_CONNECTOR_RECEIPTS_DB': 'data/connector_receipts.sqlite',
        'JANUSEC_CASE_HISTORY_DB': 'data/case_history.sqlite',
    }
    os.environ.update({name: str(state / path) for name, path in paths.items()})
    # Legacy relative runtime files are also captured by the complete state backup.
    os.chdir(state)
    validate_live_auth_configuration()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['init', 'serve', 'backup', 'restore'])
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--backup-key', type=Path)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--tenant', default='pilot-customer')
    parser.add_argument('--port', type=int, default=8443)
    parser.add_argument('--container-listen', action='store_true',
                        help='Listen inside a container; publish its port to host loopback only')
    args = parser.parse_args()
    state = args.state.resolve()
    key_file = args.backup_key.resolve() if args.backup_key else None
    archive = args.archive.resolve() if args.archive else None
    if args.command in {'init', 'backup', 'restore'} and not key_file:
        parser.error('--backup-key is required')
    if args.command in {'backup', 'restore'} and not archive:
        parser.error('--archive is required')
    if args.command == 'init':
        result = initialize(state, key_file, args.tenant)
    elif args.command == 'backup':
        result = backup(state, archive, key_file)
    elif args.command == 'restore':
        result = restore(archive, state, key_file)
    else:
        with state_lock(state):
            configure(state)
            if args.container_listen and not Path('/.dockerenv').exists():
                raise ValueError('container_listen_requires_a_container')
            os.environ['ALLOWED_ORIGINS'] = f'https://127.0.0.1:{args.port}'
            import uvicorn
            from src.api.server import app
            from src.security.pilot_boundary import PilotBoundary
            from src.security.pilot_tls import tls_paths
            cert, tls_key = tls_paths(state)
            uvicorn.run(PilotBoundary(app, state),
                        host='0.0.0.0' if args.container_listen else '127.0.0.1', port=args.port,
                        workers=1, proxy_headers=False, access_log=False, log_level='warning',
                        ssl_certfile=str(cert), ssl_keyfile=str(tls_key))
        return
    print(json.dumps(result))


if __name__ == '__main__':
    main()
