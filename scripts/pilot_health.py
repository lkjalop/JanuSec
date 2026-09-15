"""Local pilot certificate/storage monitoring; emits no credentials or evidence."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography import x509
from src.security.pilot_tls import tls_paths


def snapshot(state: Path, *, expiry_days=14, state_budget=8 * 1024**3, min_free=1024**3):
    cert, _ = tls_paths(state)
    certificate = x509.load_pem_x509_certificate(cert.read_bytes())
    now = datetime.now(timezone.utc)
    seconds = (certificate.not_valid_after_utc - now).total_seconds()
    used = sum(p.stat().st_size for p in state.rglob('*') if p.is_file())
    free = shutil.disk_usage(state).free
    alerts = []
    if now < certificate.not_valid_before_utc or seconds <= 0:
        alerts.append('certificate_not_current')
    elif seconds < expiry_days * 86400:
        alerts.append('certificate_expiring')
    if used >= state_budget * 0.8:
        alerts.append('state_budget_80_percent')
    if free < min_free + 5 * 68 * 1024**2:
        alerts.append('insufficient_storage_headroom')
    return {'checked_at': now.isoformat(), 'certificate_seconds_remaining': int(seconds),
            'state_bytes': used, 'filesystem_free_bytes': free, 'alerts': alerts,
            'hard_quota_verified': False, 'service_availability_checked': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = snapshot(args.state)
    except Exception:
        # Paths and exception bodies can contain private deployment details.
        print(json.dumps({'alerts': ['health_probe_failed']}))
        raise SystemExit(2)
    print(json.dumps(result))
    raise SystemExit(1 if result['alerts'] else 0)
