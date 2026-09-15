#!/usr/bin/env python3
import os
import json
import sqlite3
import hmac
import hashlib
from datetime import datetime
from typing import Optional, List, Dict, Any

DB = os.environ.get('APPROVAL_DB_PATH', 'data/approvals.db')


def _get_conn():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def _load_secret() -> str:
    """Load HMAC secret.

    Priority:
    - `APPROVAL_AUDIT_HMAC_KEY` plaintext env
    - `APPROVAL_AUDIT_HMAC_KMS_CIPHERTEXT` KMS ciphertext (AWS)
    - `APPROVAL_AUDIT_HMAC_AZURE_SECRET_NAME` Azure Key Vault secret name
    If KMS/Azure values are present but the relevant SDKs are not available or env not configured,
    an informative RuntimeError is raised.
    """
    plain = os.environ.get('APPROVAL_AUDIT_HMAC_KEY')
    if plain:
        return plain

    kms_ct = os.environ.get('APPROVAL_AUDIT_HMAC_KMS_CIPHERTEXT')
    if kms_ct:
        # Use AWS KMS to decrypt
        try:
            import base64
            import boto3
            kms = boto3.client('kms')
            ct = base64.b64decode(kms_ct)
            resp = kms.decrypt(CiphertextBlob=ct)
            return resp['Plaintext'].decode('utf-8')
        except Exception as e:
            raise RuntimeError(f"AWS KMS decrypt failed: {e}")

    az_name = os.environ.get('APPROVAL_AUDIT_HMAC_AZURE_SECRET_NAME')
    if az_name:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
            kv_url = os.environ.get('AZURE_KEYVAULT_URL')
            if not kv_url:
                raise RuntimeError('AZURE_KEYVAULT_URL not set')
            cred = DefaultAzureCredential()
            client = SecretClient(vault_url=kv_url, credential=cred)
            secret = client.get_secret(az_name)
            return secret.value
        except Exception as e:
            raise RuntimeError(f"Azure Key Vault secret fetch failed: {e}")

    return ''


def _fetch_events_for_token(conn: sqlite3.Connection, token: str) -> List[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute("SELECT id, event_type, payload, ts, prev_hash, hmac FROM approval_events WHERE token=? ORDER BY id ASC", (token,))
    return cur.fetchall()


def verify_token(token: str, secret: Optional[str] = None) -> Dict[str, Any]:
    """Verify a single token's HMAC chain and return a report dict."""
    conn = _get_conn()
    rows = _fetch_events_for_token(conn, token)
    conn.close()
    if secret is None:
        secret = _load_secret()
    prev = ''
    ok = True
    events = []
    for row in rows:
        payload = row['payload'] or ''
        ts = row['ts']
        mac_input = (str(prev) + token + row['event_type'] + payload + str(ts)).encode('utf-8')
        expected = hmac.new(secret.encode('utf-8'), mac_input, hashlib.sha256).hexdigest() if secret else ''
        match = expected == (row['hmac'] or '')
        events.append({
            'id': row['id'],
            'event_type': row['event_type'],
            'payload': payload,
            'ts': ts,
            'prev_hash': row['prev_hash'],
            'hmac': row['hmac'],
            'expected_hmac': expected,
            'match': match,
        })
        if not match:
            ok = False
            break
        prev = row['hmac'] or ''

    return {'token': token, 'ok': ok, 'events': events}


def verify_all(secret: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT token FROM approval_events")
    tokens = [r['token'] for r in cur.fetchall()]
    conn.close()
    reports = []
    for t in tokens:
        reports.append(verify_token(t, secret=secret))
    return reports


def human_report(report: Dict[str, Any]) -> str:
    lines = []
    lines.append(f"Token: {report['token']}")
    lines.append(f"Status: {'OK' if report['ok'] else 'INVALID'}")
    lines.append('Events:')
    for e in report['events']:
        ts = e['ts']
        try:
            ts_h = datetime.fromisoformat(ts)
            ts_s = ts_h.isoformat()
        except Exception:
            ts_s = str(ts)
        # payload summary (trimmed)
        payload_summary = e['payload'][:200].replace('\n', '\\n') if e.get('payload') else ''
        lines.append(f" - id={e['id']} type={e['event_type']} ts={ts_s} match={e['match']} payload={payload_summary}")
    return '\n'.join(lines)


def export_report_json(report: Dict[str, Any], sign: bool = True, key_id: Optional[str] = None) -> Dict[str, Any]:
    out = {
        'token': report['token'],
        'ok': report['ok'],
        'events': report['events'],
        'generated_at': datetime.utcnow().isoformat() + 'Z'
    }
    if key_id:
        out['key_id'] = key_id
    if sign:
        secret = None
        if key_id:
            try:
                from src.core.keystore import get_key
                secret = get_key(key_id)
            except Exception:
                secret = None
        if secret is None:
            secret = _load_secret()
        if not secret:
            raise RuntimeError('No HMAC secret available to sign report')
        payload = json.dumps(out, sort_keys=True).encode('utf-8')
        sig = hmac.new(secret.encode('utf-8'), payload, hashlib.sha256).hexdigest()
        out['_signature'] = sig
    return out


def export_report_csv(report: Dict[str, Any]) -> str:
    # Simple CSV: id,event_type,ts,match,payload_summary
    lines = ["id,event_type,ts,match,payload_summary"]
    for e in report['events']:
        ts = e['ts']
        payload_summary = (e.get('payload') or '')[:200].replace('"', '""').replace('\n', '\\n')
        lines.append(f"{e['id']},{e['event_type']},{ts},{e['match']},\"{payload_summary}\"")
    return '\n'.join(lines)


def verify_exported_report(exported: Dict[str, Any], secret: Optional[str] = None) -> bool:
    """Verify an exported JSON report that includes a `_signature` field."""
    if '_signature' not in exported:
        raise ValueError('no signature in exported report')
    sig = exported['_signature']
    body = dict(exported)
    del body['_signature']
    if secret is None:
        secret = _load_secret()
    if not secret:
        raise RuntimeError('no secret available to verify signature')
    payload = json.dumps(body, sort_keys=True).encode('utf-8')
    expected = hmac.new(secret.encode('utf-8'), payload, hashlib.sha256).hexdigest()
    return expected == sig


def stream_csv_for_token(token: str):
    """Generator that yields CSV lines for a token by streaming DB rows."""
    yield b"id,event_type,ts,match,payload_summary\n"
    conn = _get_conn()
    cur = conn.cursor()
    for row in cur.execute("SELECT id, event_type, payload, ts, prev_hash, hmac FROM approval_events WHERE token=? ORDER BY id ASC", (token,)):
        payload = row[2] or ''
        payload_summary = payload[:200].replace('"', '""').replace('\n', '\\n')
        line = f"{row[0]},{row[1]},{row[3]},True,\"{payload_summary}\"\n"
        yield line.encode('utf-8')
    conn.close()


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description='Verify approval_events HMAC chain')
    p.add_argument('--all', action='store_true', help='Verify all tokens')
    p.add_argument('--report', action='store_true', help='Print human-readable report')
    p.add_argument('--json', action='store_true', help='Print JSON report')
    p.add_argument('--secret', help='Provide HMAC secret directly')
    p.add_argument('--verify-file', help='Verify a signed exported JSON report file')
    p.add_argument('--export-file', help='Export signed JSON report to file for the given token')
    p.add_argument('--key-id', help='Key identifier for historic key lookup')
    p.add_argument('token', nargs='?', help='Token to verify')
    args = p.parse_args()
    secret = args.secret
    if args.all:
        reports = verify_all(secret=secret)
        if args.json:
            print(json.dumps(reports, indent=2))
        else:
            for r in reports:
                if args.report:
                    print(human_report(r))
                else:
                    print(f"{r['token']}: {'OK' if r['ok'] else 'INVALID'}")
    else:
        if not args.token:
            p.error('token required unless --all')
        r = verify_token(args.token, secret=secret)
        if args.json:
            print(json.dumps(r, indent=2))
        elif args.report:
            print(human_report(r))
        else:
            print('OK' if r['ok'] else 'INVALID')

        # verify exported signed report from file
        if args.verify_file:
            import pathlib
            pth = pathlib.Path(args.verify_file)
            if not pth.exists():
                print('verify_file not found', args.verify_file)
                raise SystemExit(2)
            obj = json.loads(pth.read_text(encoding='utf-8'))
            # support optional key id lookup: when --key-id provided, fetch key material via keystore
            key_id = getattr(args, 'key_id', None)
            key_secret = None
            if key_id:
                key_secret = _lookup_key_by_id(key_id)
            ok = verify_exported_report(obj, secret=key_secret or secret)
            print('VERIFIED' if ok else 'INVALID')

        # export signed report to file
        if args.export_file:
            if not args.token:
                p.error('--export-file requires token')
            report = verify_token(args.token, secret=secret)
            signed = export_report_json(report, sign=True)
            import pathlib
            pth = pathlib.Path(args.export_file)
            pth.write_text(json.dumps(signed, indent=2), encoding='utf-8')
            print('WROTE', str(pth))


    def _lookup_key_by_id(key_id: str) -> Optional[str]:
        """Simple keystore lookup: map key_id to env var or KMS/Azure secret name.

        Expected env vars:
          APPROVAL_KEYSTORE_MAP - JSON mapping of key_id -> {"env": "ENVNAME"} or {"kms_ct": "..."} or {"azure_secret": "name"}
        """
        mapping = os.environ.get('APPROVAL_KEYSTORE_MAP')
        if not mapping:
            return None
        try:
            mm = json.loads(mapping)
            entry = mm.get(key_id)
            if not entry:
                return None
            if 'env' in entry:
                return os.environ.get(entry['env'])
            if 'plain' in entry:
                return entry['plain']
            # try keystore file
            try:
                from src.core.keystore import get_key
                ks = get_key(key_id)
                if ks:
                    return ks
            except Exception:
                pass
            if 'kms_ct' in entry:
                os.environ['APPROVAL_AUDIT_HMAC_KMS_CIPHERTEXT'] = entry['kms_ct']
                return _load_secret()
            if 'azure_secret' in entry:
                os.environ['APPROVAL_AUDIT_HMAC_AZURE_SECRET_NAME'] = entry['azure_secret']
                return _load_secret()
        except Exception:
            return None
        return None

