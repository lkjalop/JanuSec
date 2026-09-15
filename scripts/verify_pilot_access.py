"""Verify named access and pre-parser rejection against a real loopback pilot."""
import argparse
import http.client
import json
from pathlib import Path
import ssl

import requests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--viewer', type=Path, required=True)
    parser.add_argument('--analyst', type=Path, required=True)
    parser.add_argument('--revoked', type=Path)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--port', type=int, default=8445)
    args = parser.parse_args()
    viewer = json.loads(args.viewer.read_text(encoding='utf-8'))
    analyst = json.loads(args.analyst.read_text(encoding='utf-8'))
    baseline = json.loads(args.baseline.read_text(encoding='utf-8'))
    base = f'https://127.0.0.1:{args.port}'
    session = requests.Session(); session.trust_env = False
    session.verify = str(args.state / 'tls-cert.pem')
    result = {'live_provider': False, 'checks': {}}
    checks = [
        ('viewer_reads_evidence', 'GET', f"/api/v1/assessments/{baseline['assessment_id']}/evidence?limit=1", viewer, 200),
        ('viewer_cannot_upload', 'POST', '/api/v1/assessments/upload', viewer, 403),
        ('viewer_cannot_administer', 'GET', '/api/v1/admin/scoring/get', viewer, 403),
        ('analyst_cannot_administer', 'POST', '/api/v1/admin/scoring/update', analyst, 403),
        ('analyst_cannot_execute_action', 'POST', '/api/v1/soar/execute', analyst, 403),
    ]
    if args.revoked:
        checks.append(('old_key_rejected_after_restart', 'GET', '/api/v1/assessments/',
                       json.loads(args.revoked.read_text(encoding='utf-8')), 401))
    for name, method, path, credential, expected in checks:
        response = session.request(method, base + path, headers={'x-api-key': credential['key'],
                                   'x-tenant-id': credential['tenant_id']}, timeout=30)
        result['checks'][name] = response.status_code
        assert response.status_code == expected, (name, response.status_code)
    context = ssl.create_default_context(cafile=str(args.state / 'tls-cert.pem'))
    connection = http.client.HTTPSConnection('127.0.0.1', args.port, context=context, timeout=10)
    connection.putrequest('POST', '/api/v1/assessments/upload')
    connection.putheader('x-api-key', analyst['key'])
    connection.putheader('Content-Length', str(68 * 1024**2 + 1))
    connection.endheaders()  # Send no body: rejection must occur before parsing.
    response = connection.getresponse()
    result['checks']['oversized_declared_body_rejected_before_send'] = response.status
    assert response.status == 413
    connection.close(); session.close()
    result['passed'] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
