import os
from src.core.geoip_lookup import lookup_ip
from src.core.remediation import restart_collector, refresh_api_token


def test_lookup_localhost():
    r = lookup_ip('127.0.0.1')
    assert r.get('ip') == '127.0.0.1'


def test_remediation_dry_run():
    os.environ.pop('ENABLE_AUTO_REMEDIATION', None)
    r = restart_collector('proofpoint', dry_run=True)
    assert r['status'] == 'dry_run'
    r2 = refresh_api_token('proofpoint', dry_run=True)
    assert r2['status'] == 'dry_run'
