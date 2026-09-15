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


@pytest.mark.parametrize('owner', [None, 'other'])
def test_generate_cannot_hydrate_foreign_or_ownerless_cache(monkeypatch, owner):
    from types import SimpleNamespace
    from fastapi import HTTPException
    from src.api import report_endpoints as endpoint
    from src.api.deep_analyze import persistence
    record = {'normalized_rows': [{'secret': 'foreign evidence'}]}
    if owner is not None:
        record['tenant_id'] = owner
    monkeypatch.setattr(persistence, 'REPORT_STORE', {'foreign': record})
    class Request:
        state = SimpleNamespace(tenant_id='acme', auth=None)
        headers = {}
        async def json(self):
            return {'assessment_id': 'foreign'}
    with pytest.raises(HTTPException) as exc:
        asyncio.run(endpoint.generate_report(Request(), format='json', include_model=False, include_scenarios=False, persist=False))
    assert exc.value.status_code == 404


@pytest.mark.parametrize('owner', [None, 'other', 'acme'])
def test_snapshot_requires_explicit_matching_owner(monkeypatch, owner):
    from fastapi import HTTPException
    from src.api import report_endpoints as endpoint
    monkeypatch.setattr(endpoint, 'load_snapshot_meta', lambda rid: {'tenant_id': owner} if owner else {})
    monkeypatch.setattr(endpoint, 'load_snapshot', lambda rid: {'summary': 'stored report'})
    if owner == 'acme':
        payload, tenant = endpoint._load_snapshot_payload('rpt-1', None, 'acme')
        assert payload['summary'] == 'stored report'
        assert tenant == 'acme'
    else:
        with pytest.raises(HTTPException) as exc:
            endpoint._load_snapshot_payload('rpt-1', None, 'acme')
        assert exc.value.status_code == 404


def test_snapshot_rejects_traversal_before_loading(monkeypatch):
    from fastapi import HTTPException
    from src.api import report_endpoints as endpoint
    monkeypatch.setattr(endpoint, 'load_snapshot', lambda rid: pytest.fail('loaded unsafe report ID'))
    with pytest.raises(HTTPException) as exc:
        endpoint._load_snapshot_payload('../private', None, 'acme')
    assert exc.value.status_code == 404


def test_public_report_upload_is_retired():
    from fastapi import HTTPException
    from src.api.integrations import upload_report, UploadReportPayload
    with pytest.raises(HTTPException) as exc:
        upload_report(UploadReportPayload(filename='public.html', content='<script>active()</script>'))
    assert exc.value.status_code == 410


def test_tier2_failure_does_not_return_exception_or_traceback(monkeypatch):
    import json
    from src.api import csv_endpoints
    from src.analysis import auto_llm
    marker = 'dummy-private-provider-detail'
    class BrokenClient:
        def summarize_row(self, row, context):
            raise RuntimeError(marker)
    monkeypatch.setattr(auto_llm, 'LLMAssessmentClient', BrokenClient)
    monkeypatch.setattr(auto_llm, 'detect_domain_with_confidence', lambda row: ('generic', 1.0))
    result = asyncio.run(csv_endpoints.csv_tier2_investigate({'row': {'event': 'fixture'}}, tenant_id='acme', api_key='devkey123'))
    assert result['status'] == 'error'
    assert result['traceback'] is None
    assert marker not in json.dumps(result)
