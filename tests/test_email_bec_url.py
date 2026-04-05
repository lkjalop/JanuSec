from src.core.hunt.evidence_envelope import EvidenceEnvelope
from src.core.hunt.lanes.email_bec import build as build_email_bec


def test_url_shortener_and_ip():
    env = EvidenceEnvelope({'id':'evt-url-1'})
    env.headers = {'From':'noreply@service.com'}
    env.body = 'Please click https://bit.ly/abc123 and also visit http://203.0.113.5/login for details.'
    lane = build_email_bec()
    lane(env)
    f = env.all_factors
    assert 'email:url_shortener' in f
    assert 'email:url_ip_address' in f


def test_typosquat_and_login_path():
    env = EvidenceEnvelope({'id':'evt-url-2'})
    env.headers = {'From':'no-reply@vendor.com'}
    env.body = 'Our update page: https://g00gle.com/signin and another link https://secure-google.com/login'
    lane = build_email_bec()
    lane(env)
    f = env.all_factors
    # Either typosquat or login keyword should be detected
    assert 'email:url_typosquat' in f or 'email:url_login_keyword' in f


def test_excessive_links_and_mismatch():
    env = EvidenceEnvelope({'id':'evt-url-3'})
    env.headers = {'From':'info@company.com'}
    env.body = '<a href="http://evil.com">microsoft.com</a> ' + ' '.join([f'https://site{i}.com' for i in range(7)])
    lane = build_email_bec()
    lane(env)
    f = env.all_factors
    assert 'email:link_domain_mismatch' in f
    assert 'email:excessive_links' in f
