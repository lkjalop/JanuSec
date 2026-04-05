import pytest

from src.core.attachment_analyzer import analyze_attachments


class _Runtime:
    def __init__(self, msgs):
        self.email_messages = msgs


def _msg(name, content=b'x', mime='application/octet-stream'):
    return {'filename': name, 'content': content, 'mime': mime}


def test_attachment_macro_and_executable_detection():
    rt = _Runtime([
        _msg('invoice.docm', b'123', 'application/vnd.ms-word'),
        _msg('payload.exe', b'abc', 'application/x-msdownload'),
        _msg('notes.txt', b'zzz', 'text/plain'),
    ])
    res = analyze_attachments(rt)
    names = [r.get('factor') for r in res]
    assert 'email_attachment_macro' in names
    assert 'email_attachment_executable' in names


def test_attachment_suspicious_filename():
    rt = _Runtime([_msg('urgent_payment.txt', b'data')])
    res = analyze_attachments(rt)
    assert any(r.get('factor') == 'email_attachment_suspicious' for r in res)
