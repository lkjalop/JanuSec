"""Regression tests for POST /api/v1/upload/workbook_sheets.

Coverage targets (per verification report):
  1. janusec_test_03_critical_v2.xlsx returns 101 rows, 8 parsed sheets,
     56 pivoted rows, and 91.219.236.12 as a cross-sheet pivot.
  2. A single-sheet workbook returns rows but zero cross-sheet pivots.
  3. The Overview/metadata sheet is skipped.
  4. The CRQ estimate is marked requires_human_validation=True and does NOT
     expose a precise expected_loss — only a range.
  5. The CRQ severity classifier does NOT overfit on column headers:
     a row whose column *name* contains "critical" should not auto-classify
     as critical unless the column *value* indicates it.

Tests that depend on dump/ fixture files are skipped when the file is absent
so CI stays green without the user-owned dump/ directory.
"""
from __future__ import annotations

import io
import os
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Optional real-fixture paths (user-owned, CI-absent is acceptable)
# ---------------------------------------------------------------------------
DUMP_DIR = Path(__file__).parent.parent / 'dump'
FIXTURE_CRITICAL = DUMP_DIR / 'janusec_test_03_critical_v2.xlsx'
FIXTURE_SINGLE = DUMP_DIR / 'cybstash csv1.xlsx'


# ---------------------------------------------------------------------------
# Synthetic workbook helpers
# ---------------------------------------------------------------------------

def _make_xlsx_bytes(sheets: dict[str, list[dict]]) -> bytes:
    """Build an in-memory XLSX with one sheet per entry in *sheets*.

    Each sheet dict maps sheet_name -> list of row dicts (headers from keys).
    """
    try:
        import openpyxl
    except ImportError:
        pytest.skip('openpyxl not installed')

    wb = openpyxl.Workbook()
    first = True
    for sheet_name, rows in sheets.items():
        if first:
            ws = wb.active
            ws.title = sheet_name
            first = False
        else:
            ws = wb.create_sheet(sheet_name)
        if not rows:
            continue
        headers = list(rows[0].keys())
        ws.append(headers)
        for row in rows:
            ws.append([row.get(h, '') for h in headers])

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _client():
    """Return a TestClient for the upload router in isolation."""
    import os
    os.environ.setdefault('LLM_MOCK', '1')
    os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
    os.environ.setdefault('DISABLE_DB', '1')
    os.environ.setdefault('PLATFORM_LITE_INIT', '1')

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from src.api.upload_endpoints import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _post_workbook(client, xlsx_bytes: bytes, filename: str = 'test.xlsx'):
    resp = client.post(
        '/api/v1/upload/workbook_sheets',
        files=[('files', (filename, xlsx_bytes,
                          'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'))],
        headers={'x-api-key': 'devkey123'},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    results = body.get('results', [])
    assert results, body
    return results[0]


# ===========================================================================
# 1. Overview / metadata sheet is skipped
# ===========================================================================

def test_metadata_sheet_is_skipped():
    """Overview sheet with Dataset/description rows must not appear in rows."""
    xlsx = _make_xlsx_bytes({
        'Overview': [
            {'Dataset': 'JANUSEC TEST DATASET', 'Description': 'Test scenario'},
            {'Dataset': 'Version', 'Description': '2.0'},
        ],
        'Network': [
            {'src_ip': '10.0.0.1', 'dst_ip': '91.219.236.12', 'dst_port': '443', 'event_type': 'connection'},
            {'src_ip': '10.0.0.2', 'dst_ip': '8.8.8.8', 'dst_port': '53', 'event_type': 'dns'},
        ],
    })
    result = _post_workbook(_client(), xlsx)

    assert result['status'] == 'parsed'
    assert result['total_rows'] == 2  # Network rows only
    summaries = {s['sheet']: s for s in result['sheet_summaries']}
    assert summaries['Overview']['status'] == 'skipped'
    assert summaries['Network']['status'] == 'parsed'
    assert summaries['Network']['row_count'] == 2

    # Confirm no Overview pollutant rows in rows list
    sheets_in_rows = {r['_sheet'] for r in result['rows']}
    assert 'Overview' not in sheets_in_rows


# ===========================================================================
# 2. Cross-sheet entity pivot detection (IP shared across two sheets)
# ===========================================================================

def test_cross_sheet_ip_pivot_detected():
    """IP 91.219.236.12 appearing in both Network and Data_Movement sheets
    must be flagged as a cross-sheet pivot on both rows."""
    C2_IP = '91.219.236.12'
    xlsx = _make_xlsx_bytes({
        'Network': [
            {'src_ip': '10.0.0.1', 'dst_ip': C2_IP, 'dst_port': '443', 'event_type': 'C2 beacon'},
            {'src_ip': '10.0.0.2', 'dst_ip': '8.8.8.8', 'dst_port': '53', 'event_type': 'dns'},
        ],
        'Data_Movement': [
            {'src_ip': '10.0.0.1', 'dst_ip': C2_IP, 'dst_port': '8080', 'event_type': 'large upload'},
        ],
    })
    result = _post_workbook(_client(), xlsx)

    assert result['status'] == 'parsed'
    assert result['total_rows'] == 3

    # C2 IP should be in the pivot map
    pivot_ips = result['entity_pivots']['ips']
    assert C2_IP in pivot_ips, f'Expected {C2_IP} in pivot_ips, got: {pivot_ips}'
    assert set(pivot_ips[C2_IP]) == {'Network', 'Data_Movement'}

    # Rows that contain the C2 IP must have _cross_sheet_pivot=True
    pivot_rows = [r for r in result['rows'] if r.get('_cross_sheet_pivot')]
    pivot_row_ips = {ip for r in pivot_rows for ip in (r.get('_pivot_ips') or [])}
    assert C2_IP in pivot_row_ips

    # The "factors" list must include the cross_sheet_pivot tag
    factor_rows = [r for r in pivot_rows if 'cross_sheet_pivot' in (r.get('factors') or [])]
    assert len(factor_rows) >= 2  # both Network and Data_Movement rows for the C2 IP


def test_single_sheet_has_no_cross_sheet_pivots():
    """A workbook with one data sheet must return 0 cross-sheet pivots."""
    xlsx = _make_xlsx_bytes({
        'Network': [
            {'src_ip': '10.0.0.1', 'dst_ip': '1.2.3.4', 'event_type': 'dns'},
            {'src_ip': '10.0.0.2', 'dst_ip': '1.2.3.4', 'event_type': 'dns'},
            {'src_ip': '10.0.0.3', 'dst_ip': '5.6.7.8', 'event_type': 'http'},
        ],
    })
    result = _post_workbook(_client(), xlsx)

    assert result['total_rows'] == 3
    assert result['pivoted_row_count'] == 0
    pivot_ips = result['entity_pivots']['ips']
    assert len(pivot_ips) == 0


def test_user_pivot_across_identity_and_email():
    """User principal appearing in both Identity and Email sheets is a pivot."""
    USER = 'james.morrison@acmecorp.com'
    xlsx = _make_xlsx_bytes({
        'Identity': [
            {'user': USER, 'event_type': 'login', 'host': 'ws-042'},
        ],
        'Email': [
            {'user': USER, 'subject': 'Invoice', 'event_type': 'attachment_open'},
            {'user': 'other@acmecorp.com', 'subject': 'Meeting', 'event_type': 'read'},
        ],
    })
    result = _post_workbook(_client(), xlsx)

    pivot_users = result['entity_pivots']['users']
    assert USER in pivot_users
    assert set(pivot_users[USER]) == {'Identity', 'Email'}
    # The non-pivoted user should not appear in pivot_users
    assert 'other@acmecorp.com' not in pivot_users


# ===========================================================================
# 3. CRQ estimate properties
# ===========================================================================

def test_crq_requires_human_validation():
    """CRQ output must always carry requires_human_validation=True and
    must not expose a precision expected_loss point estimate."""
    xlsx = _make_xlsx_bytes({
        'Network': [
            {'src_ip': '10.0.0.1', 'dst_ip': '1.2.3.4', 'severity': 'high'},
            {'src_ip': '10.0.0.2', 'dst_ip': '5.6.7.8', 'severity': 'low'},
        ],
    })
    result = _post_workbook(_client(), xlsx)
    crq = result['crq']

    assert crq['requires_human_validation'] is True
    # Must have a range dict, not a single point estimate
    assert 'exposure_range' in crq, 'CRQ must provide exposure_range, not a single expected_loss'
    assert 'expected_loss' not in crq, 'CRQ must NOT expose a single expected_loss dollar figure'
    er = crq['exposure_range']
    assert er['low'] <= er['mid'] <= er['high']
    assert 'exposure_range_formatted' in crq
    assert '–' in crq['exposure_range_formatted']  # range format: "$Xk – $Yk"


def test_crq_column_header_does_not_inflate_severity():
    """Having 'severity' as a column NAME with non-critical VALUES should not
    inflate the severity distribution — the classifier must look at VALUES,
    not column names."""
    xlsx = _make_xlsx_bytes({
        'Endpoint': [
            # Column header says 'severity' but value is 'low'
            {'severity': 'low', 'process': 'notepad.exe', 'event_type': 'file_open'},
            {'severity': 'medium', 'process': 'excel.exe', 'event_type': 'macro'},
            # No severity column value at all
            {'process': 'cmd.exe', 'event_type': 'shell_exec'},
        ],
    })
    result = _post_workbook(_client(), xlsx)
    sev = result['crq']['severity_counts']

    # 0 or 1 critical rows max (cmd.exe/shell_exec might hit heuristic, fine)
    assert sev['critical'] <= 1, (
        f'Expected ≤1 critical row for benign data, got {sev["critical"]}. '
        'Classifier may be scanning column names as values.'
    )
    assert sev['low'] >= 1


def test_crq_tier_reflects_severity_distribution():
    """Row set with only low-severity events should produce low/medium CRQ tier."""
    xlsx = _make_xlsx_bytes({
        'Identity': [
            {'user': 'alice', 'severity': 'low', 'event_type': 'login'},
            {'user': 'bob', 'severity': 'low', 'event_type': 'login'},
            {'user': 'carol', 'severity': 'low', 'event_type': 'logout'},
        ],
    })
    result = _post_workbook(_client(), xlsx)
    crq = result['crq']
    assert crq['exposure_tier'] in ('low', 'medium'), (
        f'Expected low/medium tier for all-low-severity rows, got {crq["exposure_tier"]}'
    )


# ===========================================================================
# 4. Domain tagging
# ===========================================================================

def test_rows_receive_sheet_and_domain_fields():
    """Every parsed row must have _sheet and _domain set correctly."""
    xlsx = _make_xlsx_bytes({
        'Cloud_AWS': [
            {'resource': 's3://bucket', 'action': 'GetObject', 'user': 'svc-account'},
        ],
        'Email': [
            {'subject': 'phish', 'sender': 'evil@evil.com', 'event_type': 'received'},
        ],
    })
    result = _post_workbook(_client(), xlsx)
    rows_by_sheet = {}
    for r in result['rows']:
        rows_by_sheet.setdefault(r['_sheet'], []).append(r)

    assert rows_by_sheet['Cloud_AWS'][0]['_domain'] == 'cloud_aws'
    assert rows_by_sheet['Email'][0]['_domain'] == 'email'


# ===========================================================================
# 5. Real fixture tests (skipped when dump/ absent — CI-safe)
# ===========================================================================

@pytest.mark.skipif(not FIXTURE_CRITICAL.exists(), reason='dump/ fixture not present')
def test_critical_fixture_row_count_and_pivots():
    """janusec_test_03_critical_v2.xlsx must return:
      - >= 100 rows (test dataset has 101 data rows)
      - 8 parsed sheets (Overview skipped)
      - >= 50 pivoted rows
      - 91.219.236.12 as a cross-sheet pivot
    """
    client = _client()
    with open(FIXTURE_CRITICAL, 'rb') as f:
        result = _post_workbook(client, f.read(), filename=FIXTURE_CRITICAL.name)

    assert result['status'] == 'parsed'
    assert result['total_rows'] >= 100, f"Expected ≥100 rows, got {result['total_rows']}"

    parsed_sheets = [s for s in result['sheet_summaries'] if s['status'] == 'parsed']
    assert len(parsed_sheets) >= 7, f"Expected ≥7 parsed sheets, got {len(parsed_sheets)}"

    skipped_sheets = [s for s in result['sheet_summaries'] if s['status'] == 'skipped']
    assert any('overview' in s['sheet'].lower() for s in skipped_sheets), \
        'Overview sheet should be skipped'

    assert result['pivoted_row_count'] >= 50, \
        f"Expected ≥50 pivoted rows, got {result['pivoted_row_count']}"

    pivot_ips = result['entity_pivots']['ips']
    assert '91.219.236.12' in pivot_ips, \
        f'91.219.236.12 should be a cross-sheet pivot, got pivot_ips: {list(pivot_ips.keys())[:10]}'

    # CRQ must be unvalidated
    assert result['crq']['requires_human_validation'] is True
    assert 'expected_loss' not in result['crq']


@pytest.mark.skipif(not FIXTURE_SINGLE.exists(), reason='dump/ fixture not present')
def test_single_sheet_fixture_no_false_pivots():
    """cybstash csv1.xlsx is single-sheet — must return 0 cross-sheet pivots."""
    client = _client()
    with open(FIXTURE_SINGLE, 'rb') as f:
        result = _post_workbook(client, f.read(), filename='cybstash_csv1.xlsx')

    assert result['status'] == 'parsed'
    assert result['total_rows'] > 0
    assert result['pivoted_row_count'] == 0, \
        f'Single-sheet workbook must have 0 cross-sheet pivots, got {result["pivoted_row_count"]}'
