"""Verify the real isolated HTTPS service without publishing credentials.

TLS is verified against the generated local certificate. This harness uses
synthetic uploads; it does not claim provider collection or customer remediation.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import math
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import statistics
import sys
import time

import jwt
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.core.acceptance_truth import evaluate_assessment_truth


def evidence_hash(evidence):
    canonical = {**evidence, 'rows': sorted(evidence['rows'], key=lambda row: row['id'])}
    return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--port', type=int, default=8443)
    parser.add_argument('--reuse', type=Path)
    parser.add_argument('--scenario', choices=['Meridian', 'Santos', 'Vesper'], default='Vesper')
    args = parser.parse_args()
    values = json.loads((args.state / 'secrets.json').read_text(encoding='utf-8'))
    entry = json.loads(values['API_KEYS_JSON'])[0]
    tenant = entry['tenant_id']
    headers = {'x-api-key': entry['key'], 'x-tenant-id': tenant}
    base = f'https://127.0.0.1:{args.port}'
    session = requests.Session(); session.trust_env = False
    session.verify = str(args.state / 'tls-cert.pem')
    result = {'profile': 'isolated-production-auth', 'live_provider': False,
              'tls_certificate_verified': False, 'checks': {}}
    assert session.get(base + '/', timeout=90).status_code == 200
    result['tls_certificate_verified'] = True
    path = '/api/v1/assessments'
    for name, supplied in [
        ('missing_key', {'x-tenant-id': tenant}),
        ('public_development_key', {'x-tenant-id': tenant, 'x-api-key': 'devkey123'}),
        ('wrong_key', {'x-tenant-id': tenant, 'x-api-key': 'not-a-configured-key'}),
    ]:
        status = session.get(base + path, headers=supplied, timeout=30).status_code
        result['checks'][name] = status
        assert status in (401, 403), (name, status)
    assert session.get(base + path, headers=headers, timeout=30).status_code == 200
    result['checks']['configured_key'] = 200
    for protected in ('/api/v1/admin/scoring/get', '/api/v1/integrations/nonexistent/config'):
        status = session.get(base + protected, headers={'x-tenant-id': tenant}, timeout=30).status_code
        assert status == 401, (protected, status)
    result['checks']['admin_and_integration_auth_required'] = True
    now = int(time.time())
    def token(tid, expires):
        return jwt.encode({'sub': 'isolation-verifier', 'tenant_id': tid, 'scopes': ['*'],
                           'iss': values['JWT_ISSUER'], 'aud': values['JWT_AUDIENCE'], 'exp': expires},
                          values['JWT_SECRET'], algorithm='HS256')
    expired = {'Authorization': 'Bearer ' + token(tenant, now - 60), 'x-tenant-id': tenant}
    assert session.get(base + path, headers=expired, timeout=30).status_code == 401
    result['checks']['expired_jwt'] = 401
    if args.reuse:
        previous = json.loads(args.reuse.read_text(encoding='utf-8'))
        aid = previous['assessment_id']
    else:
        started = time.perf_counter()
        paths = sorted(p for p in (ROOT / 'tests/fixtures/telemetry_corpora' / args.scenario).iterdir() if p.suffix != '.md')
        streams = [p.open('rb') for p in paths]
        try:
            response = session.post(base + path + '/upload', headers=headers,
                                    files=[('files', (p.name, f)) for p, f in zip(paths, streams)], timeout=120)
        finally:
            for stream in streams: stream.close()
        assert response.status_code == 202, response.status_code
        aid = response.json()['assessment_id']
        print(json.dumps({'stage': 'uploaded', 'assessment_id': aid}), flush=True)
        deadline = time.monotonic() + 900
        while True:
            response = session.get(base + path + f'/{aid}/progress/poll', headers=headers, timeout=60)
            assert response.ok, response.status_code
            progress = response.json()
            if progress['status'] in {'ready', 'failed', 'cancelled'}:
                break
            assert time.monotonic() < deadline, 'ingestion_timeout'
            time.sleep(2)
        assert progress['status'] == 'ready', progress.get('error')
        result['ingestion_seconds'] = round(time.perf_counter() - started, 3)
        result['stored_records'] = progress['row_count']
        assert result['stored_records'] == {'Meridian': 24438, 'Santos': 43834, 'Vesper': 98750}[args.scenario]
    result['assessment_id'] = aid
    foreign = {'Authorization': 'Bearer ' + token('foreign-customer', now + 3600), 'x-tenant-id': 'foreign-customer'}
    evidence_path = path + f'/{aid}/evidence?limit=1'
    status = session.get(base + evidence_path, headers=foreign, timeout=60).status_code
    assert status == 404, status
    result['checks']['foreign_evidence'] = status
    status = session.get(base + evidence_path, headers={**headers, 'x-tenant-id': 'foreign-customer'}, timeout=60).status_code
    assert status == 403, status
    result['checks']['tenant_header_override'] = status
    cases = session.get(base + path + f'/{aid}/cases', headers=headers, timeout=90)
    assert cases.ok, cases.status_code
    cases = cases.json()['cases']
    result['case_hashes'] = {c['case_id']: c.get('content_hash') for c in cases}
    assert all(result['case_hashes'].values()), 'missing_case_hash'
    truth = json.loads((ROOT / 'tests/fixtures/ground_truth' / (args.scenario.lower() + '.json')).read_text(encoding='utf-8'))
    result['truth'] = evaluate_assessment_truth(cases, truth)
    failures = [item for group in result['truth']['details'].values() for item in group if not item['passed']]
    assert not failures, ('ground_truth_failed', failures)
    selected = previous.get('selected_case') if args.reuse else None
    selected = selected or next(c['case_id'] for c in cases if c.get('status') != 'background')
    result['selected_case'] = selected
    view = session.get(base + path + f'/{aid}/case-view', headers=headers, params={'case_id': selected}, timeout=90)
    assert view.ok, view.status_code
    view = view.json()
    result['evidence_hash'] = evidence_hash(view['evidence'])
    result['evidence_hash_algorithm'] = 'canonical-rows-by-id/v1'
    result['historical_receipt'] = view['report_context']['historical_receipt']
    result['evidence_window'] = {k:v for k,v in view['evidence'].items() if k != 'rows'}
    if args.reuse and previous.get('selected_case'):
        assert result['case_hashes'] == previous['case_hashes'], 'case partition changed after restore'
        receipt = previous['historical_receipt']
        timestamp = datetime.fromisoformat(receipt['recorded_at']).timestamp()
        cutoff = datetime.fromtimestamp(math.ceil(timestamp * 1000) / 1000, timezone.utc).isoformat()
        response = session.get(base + path + f'/{aid}/case-view', headers=headers,
                               params={'case_id': receipt['case_id'], 'as_known_at': cutoff}, timeout=90)
        assert response.ok, response.status_code
        assert response.json()['report_context']['historical_receipt']['receipt_hash'] == receipt['receipt_hash']
        historical_evidence = response.json()['evidence']
        if previous.get('evidence_hash_algorithm') == 'canonical-rows-by-id/v1':
            assert evidence_hash(historical_evidence) == previous['evidence_hash']
        else:
            # Preserve and verify older order-sensitive receipts before comparing contents.
            assert hashlib.sha256(json.dumps(historical_evidence, sort_keys=True).encode()).hexdigest() == previous['evidence_hash']
        assert result['evidence_hash'] == evidence_hash(historical_evidence), 'case evidence contents changed after restore'
        result['restored_historical_receipt_matches'] = True
    def read_request(_):
        # Separate client per thread; requests.Session is not shared across threads.
        with requests.Session() as reader:
            reader.trust_env = False
            start = time.perf_counter()
            response = reader.get(base + evidence_path, headers=headers, verify=str(args.state / 'tls-cert.pem'), timeout=60)
            return response.status_code, time.perf_counter() - start
    with ThreadPoolExecutor(max_workers=4) as executor:
        samples = list(executor.map(read_request, range(40)))
    assert all(status == 200 for status, _ in samples)
    durations = sorted(duration for _, duration in samples)
    result['bounded_read_load'] = {'clients': 4, 'requests': 40, 'errors': 0,
                                   'p50_seconds': round(statistics.median(durations), 3),
                                   'p95_seconds': round(durations[37], 3),
                                   'max_seconds': round(max(durations), 3), 'soak_certification': False}
    result['passed'] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
