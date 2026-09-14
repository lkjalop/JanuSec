"""Real Chromium corpus uploads and case/history/export checks; no mocked routes.

Run against an isolated loopback preview. Synthetic fixtures prove only their
explicit assertions, never live-provider reliability or general detection recall.
"""
import argparse
import hashlib
import json
import math
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.core.acceptance_truth import evaluate_assessment_truth


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', default='http://127.0.0.1:8083')
    parser.add_argument('--datasets', type=Path, default=ROOT / 'tests/fixtures/telemetry_corpora')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--scenario', nargs='+', default=['Meridian', 'Santos', 'Vesper'])
    parser.add_argument('--reuse', help='JSON object mapping scenario names to existing assessment IDs')
    args = parser.parse_args()
    base = args.base_url.rstrip('/')
    if urlsplit(base).hostname not in {'localhost', '127.0.0.1', '::1'}:
        parser.error('This development-key harness requires an isolated loopback server.')
    args.output.mkdir(parents=True, exist_ok=True)
    reuse = json.loads(args.reuse) if args.reuse else {}
    manifest = {item['path']: item for item in json.loads((ROOT / 'tests/fixtures/telemetry_corpora/manifest.json').read_text(encoding='utf-8'))}
    expected_rows = {'meridian': 24438, 'santos': 43834, 'vesper': 98750}
    results = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        for scenario in args.scenario:
            result = {'scenario': scenario, 'mocked_routes': False, 'errors': [], 'http_errors': [], 'tabs': []}
            started = time.perf_counter()
            context = browser.new_context(viewport={'width': 1600, 'height': 1000}, timezone_id='UTC')
            context.add_init_script('if (location.origin === ' + json.dumps(base) + ") { localStorage.setItem('apiKey','devkey123'); localStorage.setItem('tenantId','default'); }")
            context.on('page', lambda p: p.on('pageerror', lambda e: result['errors'].append(str(e))))
            context.on('response', lambda r: result['http_errors'].append({'path': urlsplit(r.url).path, 'status': r.status}) if r.status >= 400 else None)
            headers = {'x-api-key': 'devkey123', 'x-tenant-id': 'default'}
            page = context.new_page()
            page.set_default_timeout(30000)

            def get(path):
                response = context.request.get(base + path, headers=headers, timeout=90000)
                assert response.ok, f'{path}: HTTP {response.status}'
                return response.json()

            try:
                files = sorted(p for p in (args.datasets / scenario).iterdir() if p.is_file() and p.suffix.lower() != '.md')
                result['input_receipts'] = []
                for path in files:
                    relative = f'{scenario}/{path.name}'
                    with path.open('rb') as stream:
                        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                    assert relative in manifest and digest == manifest[relative]['sha256'], f'Unrecognized or changed truth corpus: {relative}'
                    result['input_receipts'].append({'path': relative, 'sha256': digest, 'bytes': path.stat().st_size})
                assert len(files) == sum(name.startswith(scenario + '/') for name in manifest), 'Incomplete truth corpus'
                aid = reuse.get(scenario)
                page.goto(base + '/', wait_until='domcontentloaded')
                if not aid:
                    result['files'] = len(files)
                    result['bytes'] = sum(p.stat().st_size for p in files)
                    page.locator('#newButton').click()
                    page.locator('#fileInput').set_input_files([str(p) for p in files])
                    with page.expect_response('**/api/v1/assessments/upload', timeout=120000) as uploaded:
                        page.locator('#uploadForm button[type=submit]').click()
                    assert uploaded.value.ok
                    aid = uploaded.value.json()['assessment_id']
                result['assessment_id'] = aid
                (args.output / f'{scenario.lower()}-running.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
                last_stage = None
                deadline = time.monotonic() + 1200
                while True:
                    progress = get(f'/api/v1/assessments/{aid}/progress/poll')
                    state = (progress['status'], progress['stage'], progress['percent'])
                    if state != last_stage:
                        print(json.dumps({'scenario': scenario, 'progress': progress}), flush=True)
                        last_stage = state
                    if progress['status'] in {'ready', 'failed', 'cancelled'}:
                        break
                    assert time.monotonic() < deadline, 'Assessment did not reach a terminal state within 20 minutes'
                    page.wait_for_timeout(2000)
                result['progress'] = progress
                result['upload_to_ready_seconds'] = None if scenario in reuse else round(time.perf_counter() - started, 2)
                assert progress['status'] == 'ready' and progress['percent'] == 100
                page.goto(base + '/?assessment=' + aid, wait_until='domcontentloaded')
                expect(page.locator('#caseMeta')).to_contain_text('100% processed', timeout=120000)
                cases = get(f'/api/v1/assessments/{aid}/cases')['cases']
                (args.output / f'{scenario.lower()}-cases.json').write_text(json.dumps(cases, indent=2), encoding='utf-8')
                result['case_count'] = len(cases)
                result['active_cases'] = sum(c.get('status') != 'background' for c in cases)
                fixture = json.loads((ROOT / 'tests/fixtures/ground_truth' / f'{scenario.lower()}.json').read_text(encoding='utf-8'))
                result['truth'] = evaluate_assessment_truth(cases, fixture)
                result['expected_positive_assertions'] = len(fixture.get('must_detect', []))
                result['evidence_total'] = get(f'/api/v1/assessments/{aid}/evidence?limit=1')['total']
                assert result['evidence_total'] == progress['row_count'], 'Stored evidence count differs from job count'
                assert result['evidence_total'] == expected_rows[scenario.lower()], 'Stored evidence differs from independently parsed corpus count'
                values = page.locator('#casePartitionSelector option').evaluate_all('xs => xs.map(x => x.value)')
                selected = page.locator('#casePartitionSelector').input_value()
                result['partitions_switched'] = 0
                for value in [v for v in values if v != selected][:2] + [selected]:
                    if not value:
                        continue
                    page.locator('#casePartitionSelector').select_option(value)
                    expect(page.locator('#caseTitle')).to_have_text(value)
                    result['partitions_switched'] += 1
                for tab in ['Causal graph', 'Detailed timeline', 'Retrieval trace', 'Action plan', 'Evidence']:
                    page.get_by_role('tab', name=tab, exact=True).click()
                    result['tabs'].append({'tab': tab, 'count': page.locator('#resultCount').inner_text()})
                assert page.locator('[data-evidence]').count() > 0
                page.locator('[data-evidence]').first.click()
                expect(page.locator('#inspectorContent')).to_contain_text('evidence')
                result['evidence_drilldown'] = True
                page.screenshot(path=str(args.output / f'{scenario.lower()}-desktop.png'), full_page=True)
                view = get(f'/api/v1/assessments/{aid}/case-view?case_id={selected}')
                result['selected_case'] = view['case']
                result['breach_summary'] = view.get('breach_summary')
                result['coverage_gaps'] = view.get('coverage_gaps')
                result['evidence_window'] = {k: v for k, v in view['evidence'].items() if k != 'rows'}
                assert view['evidence']['truncated'] == (view['evidence']['returned'] < view['evidence']['total'])
                result['attack_milestones'] = view.get('attack_story', {}).get('milestones', [])
                result['action_count'] = len(view.get('action_plan', {}).get('actions', []))
                result['control_impacts'] = view.get('control_impacts', [])
                if result['expected_positive_assertions']:
                    assert result['attack_milestones'], 'Detected attack phases disappeared from the case projection'
                    allowed_ids = set(next(c for c in cases if c['case_id'] == selected)['evidence_ids'])
                    assert all(set(m['evidence_ids']) <= allowed_ids and m['evidence_ids'] for m in result['attack_milestones'])
                    if scenario.lower() == 'vesper':
                        exfil = next(m for m in result['attack_milestones'] if m['phase_id'] == 'cloud_object_exfiltration')
                        assert len(exfil['evidence_ids']) >= 30, 'Cumulative exfiltration lost contributing transfers'
                receipt = view['report_context']['historical_receipt']
                stamp = datetime.fromisoformat(receipt['recorded_at']).timestamp()
                cutoff = datetime.fromtimestamp(math.ceil(stamp * 1000) / 1000, timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
                page.locator('#knownAt').fill(cutoff.rstrip('Z').rstrip('0').rstrip('.'))
                page.locator('#knownAt').dispatch_event('change')
                expect(page.locator('#caseMeta')).to_contain_text('Recorded view:')
                historical = get(f'/api/v1/assessments/{aid}/case-view?case_id={selected}&as_known_at={cutoff}')
                assert historical['report_context']['historical_receipt']['receipt_hash'] == receipt['receipt_hash']
                assert historical['evidence'] == view['evidence']
                with page.expect_popup() as exported:
                    page.locator('#exportGrcButton').click()
                export = exported.value
                export.wait_for_load_state()
                assert receipt['receipt_hash'] in export.locator('body').inner_text()
                (args.output / f'{scenario.lower()}-historical-export.html').write_text(export.content(), encoding='utf-8')
                export.close()
                page.reload(wait_until='domcontentloaded')
                expect(page.locator('#caseMeta')).to_contain_text('Recorded view:')
                assert page.locator('#casePartitionSelector').input_value() == selected
                result['historical_export_receipt_matches'] = True
                page.set_viewport_size({'width': 390, 'height': 844})
                result['mobile_layout'] = page.evaluate('''() => ({
                    viewport: innerWidth,
                    document_width: document.documentElement.scrollWidth,
                    case_title_width: document.getElementById('caseTitle').scrollWidth
                })''')
                assert result['mobile_layout']['document_width'] <= result['mobile_layout']['viewport'], f"Mobile document overflow: {result['mobile_layout']}"
                page.screenshot(path=str(args.output / f'{scenario.lower()}-mobile.png'), full_page=True)
                result['mobile_no_horizontal_overflow'] = True
                failed_truth = [item for assertions in result['truth']['details'].values() for item in assertions if not item['passed']]
                result['failed_truth_assertions'] = failed_truth
                assert not failed_truth, f'Production case truth mismatch: {failed_truth}'
                assert not result['errors'] and not result['http_errors'], 'Browser JavaScript or HTTP errors'
                result['passed'] = True
            except Exception as exc:
                result['passed'] = False
                result['failure'] = f'{type(exc).__name__}: {exc}'
                result['failure_traceback'] = traceback.format_exc()
                page.screenshot(path=str(args.output / f'{scenario.lower()}-failure.png'), full_page=True)
            finally:
                result['elapsed_seconds'] = round(time.perf_counter() - started, 2)
                (args.output / f'{scenario.lower()}-verified.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
                results.append(result)
                print(json.dumps({k: result.get(k) for k in ('scenario', 'assessment_id', 'passed', 'failure', 'elapsed_seconds', 'evidence_total', 'truth')}), flush=True)
                context.close()
        browser.close()
    (args.output / 'corpus-browser-summary.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    return 0 if all(r['passed'] for r in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
