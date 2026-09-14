import asyncio
import pytest
from src.api.report_endpoints import _simple_sanitize


def test_fallback_escapes_executable_markup():
    payload = '<img src=x onerror=alert(1)><svg/onload=alert(2)>'
    assert '<' not in _simple_sanitize(payload)


def test_html_pdf_input_has_no_resource_urls(monkeypatch):
    from src.api import report_endpoints as endpoint
    from src.reporting import export
    captured = []
    def render(html):
        captured.append(html)
        return b'%PDF-test'
    monkeypatch.setattr(export, 'export_pdf_bytes_from_html', render)
    class Request:
        async def json(self):
            return {'html': '<style>@import "http://127.0.0.1";</style><img src="file:///private"><iframe src="http://169.254.169.254"></iframe><p style="background:url(http://localhost)">Report</p>'}
    response = asyncio.run(endpoint.generate_pdf_from_html_endpoint(Request()))
    assert response.media_type == 'application/pdf'
    assert len(captured) == 1
    from html.parser import HTMLParser
    class Audit(HTMLParser):
        def handle_starttag(self, tag, attrs):
            assert tag not in ('img', 'style', 'iframe', 'script', 'link', 'object')
            assert not attrs
    Audit().feed(captured[0])


def test_weak_rsa_key_generation_is_rejected():
    import rsa
    with pytest.raises(ValueError, match='2048'):
        rsa.newkeys(1024)
