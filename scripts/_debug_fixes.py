"""Debug script for tracing remaining report fix issues."""
import os, time
os.environ['LLM_MOCK'] = '1'
os.environ.setdefault('DISABLE_DB', '1')
from pathlib import Path
from scripts.offline_replay_harness import _load_rows
from src.analysis.offline_workbook_assessment import build_offline_workbook_assessment
from src.reporting.executive_reporting import (
    _extract_report, _build_evidence_lookup, _plain_english_alerts, _latest_ts,
    _window_counts, TREND_WINDOWS,
)
from src.reporting.persona_template_packs import enrich_canonical_report, _humanize_resource

for org, pack in [('contoso.dev', 'azure_contoso_dev'), ('123456789012', 'aws_123456789012')]:
    print(f'\n=== {org} ===')
    rows = _load_rows(Path(f'dump/tests/janusec_test_packs/{pack}'))
    assessment = build_offline_workbook_assessment(rows, assessment_id='dbg', org=org, auto_llm=True)
    report = enrich_canonical_report(_extract_report(assessment))
    ev_lookup, ev_rows = _build_evidence_lookup(report)
    alerts = _plain_english_alerts(report, ev_lookup)
    print('Key evidence refs:')
    for a in alerts:
        print(f'  {a["kind"]:22} refs={a["evidence_refs"]}')

    all_rows = [r for r in (report.get('rows') or []) if isinstance(r, dict)]
    data_end = _latest_ts(all_rows)
    now = time.time()
    print(f'data_end={data_end:.0f}  now={now:.0f}  diff_days={(now-data_end)/86400:.0f}')
    wc = _window_counts(all_rows, now)
    print('window_counts anchored to NOW:')
    for w, bucket in wc.items():
        total = sum(bucket.values())
        print(f'  {w}: {total} items')

    # check S3 bucket in evidence rows
    appendix = report.get('evidence_appendix') or {}
    for ev in (appendix.get('source_evidence_rows') or []):
        if 'guardduty' in str(ev.get('source_kind') or '').lower():
            print(f'  GD row resource: {ev.get("resource")!r}')
    # ARM humanise test
    arm = '/SUBSCRIPTIONS/sub-12345678-abcd-0001/RESOURCEGROUPS/rg-prod-eastus/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/nsg-prod-eastus-001'
    print(f'ARM humanize: {_humanize_resource(arm)!r}')
