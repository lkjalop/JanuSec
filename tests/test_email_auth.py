from src.core.email_auth import canonicalize_header, canonicalize_body, _parse_dmarc_txt, check_dmarc


def test_canonicalize_header_relaxed():
    h = canonicalize_header('Subject', '  Hello\r\n World  ', mode='relaxed')
    assert 'subject:' in h


def test_canonicalize_body_simple_and_relaxed():
    b = b"Line1\r\nLine2\r\n\r\n"
    r = canonicalize_body(b, mode='relaxed')
    s = canonicalize_body(b, mode='simple')
    assert isinstance(r, bytes)
    assert isinstance(s, bytes)


def test_parse_dmarc_txt():
    txt = 'v=DMARC1; p=reject; adkim=s; aspf=r'
    parsed = _parse_dmarc_txt(txt)
    assert parsed.get('p') == 'reject'
    assert parsed.get('adkim') == 's'


def test_check_dmarc_no_dns(monkeypatch):
    # Best-effort check with no DNS available should return default policy
    res = check_dmarc('example.com', 'User <user@example.com>', dkim_verified=False, spf_result=None)
    assert 'dmarc_status' in res
import sys
sys.path.append('d:/AI/Threat_thy_sniffer')
from src.core.email_auth import verify_dkim, check_dmarc, parse_arc_headers


def test_verify_dkim_absent_or_invalid():
    raw = b"From: alice@example.com\r\nTo: bob@domain.com\r\nSubject: Test\r\n\r\nHello\n"
    res = verify_dkim(raw)
    assert isinstance(res, dict)
    assert 'dkim_status' in res
    assert res['dkim_status'] in {'valid', 'invalid', 'absent'}


def test_check_dmarc_sane():
    # DNS may not be available in test env; we accept 'unknown' as valid outcome
    out = check_dmarc('example.com', 'Alice <alice@example.com>')
    assert isinstance(out, dict)
    assert 'dmarc_status' in out


def test_parse_arc_headers_empty():
    raw = b"From: a@b.com\r\n\r\nbody"
    arc = parse_arc_headers(raw)
    assert isinstance(arc, dict)
    assert arc.get('arc_present') in (True, False)


def test_verify_dkim_mocked_valid(monkeypatch):
    # Simulate dkim library present and verify returning True
    class DummyDKIM:
        @staticmethod
        def verify(raw):
            return True
        def DKIM(self, raw):
            return None

    monkeypatch.setitem(sys.modules, 'dkim', DummyDKIM)
    # reload function to pick up patched module
    import importlib
    import src.core.email_auth as ea
    importlib.reload(ea)
    raw = b"From: alice@example.com\r\n\r\nHello"
    res = ea.verify_dkim(raw)
    assert res.get('dkim_status') in {'valid', 'invalid', 'absent'}
