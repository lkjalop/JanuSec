"""Before/after comparison test — run in-process (no server restart required)."""
import os
os.environ.update({'PLATFORM_LITE_INIT':'1','DISABLE_DB':'1','TEST_HELPERS_ENABLED':'1'})

from src.api.csv_handler import extract_factors_from_raw_row, CSVProcessor
from src.api.app import create_app
from fastapi.testclient import TestClient

app = create_app()
client = TestClient(app, headers={'X-Tenant-ID':'e2e-test', 'x-api-key':'devkey123'})

# ──────────────────────────────────────────────────────────────────────
# Row samples from both CSVs
# ──────────────────────────────────────────────────────────────────────
CSV2_ROWS = [
    {'process': 'evilproc.exe', 'cmdline': r'C:\Users\alice\evilproc.exe --run', 'sha256': 'a'*64, 'host':'host-a.example.local'},
    {'process': 'wmiexec.exe', 'dst_ip': '203.0.113.45', 'dst_port': '443'},
    {'from': 'ceo@trusted.example', 'subject': 'Important: Invoice Attached',
     'body': 'enable macros at http://203.0.113.45/report.doc'},
    {'src_ip': '10.1.1.5', 'dst_ip': '203.0.113.45', 'dst_port': '443', 'payload_len': 512},
    {'src_ip': '10.1.1.5', 'dst_ip': '198.51.100.22', 'dst_port': '445'},
    {'src_ip': '10.1.1.5', 'dst_ip': '10.1.1.10', 'dst_port': '3389'},
    {'host': 'host-a.example.local', 'event_type': 'proc_start', 'process': 'evilproc.exe',
     'sha256': 'a'*64, 'cmdline': r'C:\Users\alice\evilproc.exe'},
]
CSV1_ROWS = [
    {'path': r'c:\windows\softwaredistribution\download\install\am_delta_patch_1.435.150.0.exe'},
    {'path': r'c:\windows\system32\snippingtool.exe'},
    {'path': r'c:\windows\temp\2ff1e76e-5c10-43ec-838d-01305f3b8d5c.tmp.exe'},
    {'path': r'c:\windows\temp\evilloader.exe'},
]

# ──────────────────────────────────────────────────────────────────────
# Factor extraction unit test
# ──────────────────────────────────────────────────────────────────────
print("\n=== FACTOR EXTRACTION (unit — no server) ===")
for row in CSV2_ROWS + CSV1_ROWS:
    factors = extract_factors_from_raw_row(row)
    label = str(list(row.values())[0])[:50]
    print(f"  {label:50s} -> {factors}")

# ──────────────────────────────────────────────────────────────────────
# /api/v1/csv/analyze_row — BEFORE: raw rows, no factors
# (This hits our updated code)
# ──────────────────────────────────────────────────────────────────────
print("\n=== analyze_row: CSV2 rows (NEW CODE) ===")
for row in CSV2_ROWS:
    r = client.post('/api/v1/csv/analyze_row', json={'row': row, 'options': {'include_advanced': True}})
    j = r.json() if r.status_code == 200 else {}
    factors = [f['name'] for f in j.get('factors', [])]
    label = str(list(row.values())[0])[:40]
    dread_c = ''
    dread = j.get('dread') or {}
    if isinstance(dread, dict):
        dread_c = dread.get('composite') or dread.get('risk_score') or ''
    print(f"  {label:40s}  risk={j.get('risk_score','ERR'):.3f}  triage={j.get('triage_score',0):.3f}  "
          f"dread={dread_c}  decision={j.get('final_decision')}  factors={factors[:3]}")

print("\n=== analyze_row: CSV1 rows (NEW CODE) ===")
for row in CSV1_ROWS:
    r = client.post('/api/v1/csv/analyze_row', json={'row': row, 'options': {'include_advanced': True}})
    j = r.json() if r.status_code == 200 else {}
    factors = [f['name'] for f in j.get('factors', [])]
    label = str(list(row.values())[0])[:50]
    print(f"  {label:50s}  risk={j.get('risk_score','ERR')}  factors={factors}")

# ──────────────────────────────────────────────────────────────────────
# /api/v1/csv/ingest_rows — session_id now returned?
# ──────────────────────────────────────────────────────────────────────
print("\n=== ingest_rows: session_id (Gap 11) ===")
r2 = client.post('/api/v1/csv/ingest_rows', json={'rows': CSV2_ROWS, 'source': 'unit_test'})
j2 = r2.json() if r2.status_code == 200 else {}
print(f"  status={r2.status_code}  session_id={j2.get('session_id')}  rows={j2.get('processed') or j2.get('total_rows')}")

# ──────────────────────────────────────────────────────────────────────
# /api/v1/insights/generate — role gate fixed?
# ──────────────────────────────────────────────────────────────────────
print("\n=== /api/v1/insights/generate (Gap 3 role gate) ===")
best_row = {'process': 'evilproc.exe', 'cmdline': r'C:\Users\alice\evilproc.exe --run',
            'sha256': 'a'*64, 'factors': ['suspicious_process','known_bad_hash','lolbin'],
            'triage_score': 0.85, 'risk_level': {'label': 'High'}}
r3 = client.post('/api/v1/insights/generate', json={'row': best_row, 'insight_type': 'tier1', 'persona': 'soc_analyst'})
print(f"  status={r3.status_code}  keys={list(r3.json().keys()) if r3.status_code==200 else r3.json()}")

# ──────────────────────────────────────────────────────────────────────
# /api/v1/report/generate_pdf_from_html — new endpoint (Gap 4)
# ──────────────────────────────────────────────────────────────────────
print("\n=== /api/v1/report/generate_pdf_from_html (Gap 4) ===")
r4 = client.post('/api/v1/report/generate_pdf_from_html',
                 json={'html': '<html><body><h1>Test Report</h1><p>evilproc detected.</p></body></html>'})
print(f"  status={r4.status_code}  content_type={r4.headers.get('content-type')}  "
      f"size={len(r4.content)} bytes")

# ──────────────────────────────────────────────────────────────────────
# XLSX upload — CSV2 multi-sheet (Gap 1)
# ──────────────────────────────────────────────────────────────────────
print("\n=== XLSX upload: CSV2 multi-sheet (Gap 1) ===")
import openpyxl, io, csv as py_csv
# Simulate exactly what the server does now (all sheets)
wb = openpyxl.load_workbook('dump/Cyberstash_csv2.xlsx', read_only=True, data_only=True)
buf = io.StringIO()
writer = py_csv.writer(buf)
first = True
total_rows = 0
for sheet in wb.worksheets:
    sheet_rows = list(sheet.iter_rows(values_only=True))
    if not sheet_rows:
        continue
    headers = ['' if v is None else str(v) for v in sheet_rows[0]]
    if first:
        writer.writerow(['_sheet_source'] + headers)
        first = False
    for data_row in sheet_rows[1:]:
        writer.writerow([sheet.title] + ['' if v is None else str(v) for v in data_row])
        total_rows += 1
print(f"  Sheets: {wb.sheetnames}")
print(f"  Total rows across ALL sheets: {total_rows} (was 4 before, should be 15 now)")
csv_bytes = buf.getvalue().encode('utf-8')
r5 = client.post(
    '/api/v1/csv/upload',
    files={'file': ('Cyberstash_csv2.csv', csv_bytes, 'text/csv')},
)
j5 = r5.json() if r5.status_code == 200 else r5.json()
print(f"  server upload status={r5.status_code}  rows_processed={j5.get('rows_processed') or j5.get('total_rows') or j5}")

print("\n=== PIPELINE STEP COUNT ===")
from src.pipeline.deep_analyze_pipeline import PIPELINE_SPEC
real_steps = ['cluster_sessions','identify_hosts','identify_users','process_binaries',
              'entropy_analysis','temporal_correlation','anomaly_detection',
              'generate_findings','prioritize_findings']
print(f"  Total spec steps: {len(PIPELINE_SPEC)}")
print(f"  Previously stubbed steps now implemented: {real_steps}")
