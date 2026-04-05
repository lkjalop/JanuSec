#!/usr/bin/env python3
"""
Seed a deterministic mini-attack into the local API to demo:
email -> VPN (remote access) -> RDP -> DB access -> egress IP.

Usage:
  python scripts/seed_mini_attack.py [--api http://localhost:8080] [--key devkey123]
"""
import argparse, json, sys
import time

try:
    import requests
except Exception:
    print("ERROR: requests not installed. pip install requests", file=sys.stderr)
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--api', default='http://localhost:8080')
    ap.add_argument('--key', default='devkey123')
    ap.add_argument('--tenant', default=None)
    args = ap.parse_args()
    headers = {'x-api-key': args.key}
    if args.tenant:
        headers['X-Tenant-ID'] = args.tenant

    # 1) Email → user
    email_event = {
        'message_id': 'phish-001',
        'from': 'support@paypa1.example',
        'to': 'alice@corp.local',
        'subject': 'Urgent: Update Payment',
        'spf': 'fail', 'dkim': 'fail', 'dmarc': 'fail',
        'timestamp': int(time.time())
    }
    try:
        requests.post(f"{args.api}/api/v1/email/ingest", headers=headers, json=email_event, timeout=5)
    except Exception:
        pass

    # 2) Remote access (VPN) from rare IP to alice
    ra = {
        'src_ip': '185.34.12.89', 'user': 'alice@corp.local', 'dest_host': 'bastion-01',
        'dest_port': 443, 'protocol': 'vpn', 'timestamp': int(time.time()),
        'signals': {'mfa_used': False, 'user_geo_new_country': True}
    }
    try:
        requests.post(f"{args.api}/api/v1/remote_access/ingest", headers=headers, json=ra, timeout=5)
    except Exception:
        pass

    # 3) Lateral RDP to DB jump host
    rdp = {
        'src': '10.0.5.21', 'dst': '10.0.9.50', 'dst_port': 3389, 'proto': 'tcp', 'bytes': 15000000
    }
    try:
        requests.post(f"{args.api}/api/v1/graph/network/ingest", headers=headers, json={'flows':[rdp]}, timeout=5)
    except Exception:
        pass

    # 4) DB access (data domain)
    data_access = {
        'user': 'alice@corp.local', 'resource': 'db:customers', 'action': 'select', 'records': 2300000,
        'pii': True, 'host': 'db-prod-01'
    }
    try:
        requests.post(f"{args.api}/api/v1/graph/cloud/ingest", headers=headers, json={'resources':[{'id':'db:customers','principals':['user:alice@corp.local'],'destinations':['host:db-prod-01'],'public':False}]}, timeout=5)
    except Exception:
        pass
    try:
        # Some deployments accept data events via identity preview/ingest; keep as no-op if not present
        requests.post(f"{args.api}/api/v1/graph/identity/ingest", headers=headers, json=data_access, timeout=5)
    except Exception:
        pass

    # 5) Egress to external IP
    egress = {'src': '10.0.9.50', 'dst': '185.34.12.89', 'dst_port': 443, 'proto': 'tcp', 'bytes': 500000000}
    try:
        requests.post(f"{args.api}/api/v1/graph/network/ingest", headers=headers, json={'flows':[egress]}, timeout=5)
    except Exception:
        pass

    print("Seeded mini-attack chain.")


if __name__ == '__main__':
    main()

