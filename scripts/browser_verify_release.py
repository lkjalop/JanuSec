"""Real-backend upload, case/history/export and navigation regression journey."""
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--base-url', default='http://127.0.0.1:8081')
parser.add_argument('--output', type=Path, default=Path('tmp_preview/browser'))
args = parser.parse_args()
OUT = args.output
OUT.mkdir(parents=True, exist_ok=True)
BASE = args.base_url
AID = None
result = {'errors': [], 'http_errors': [], 'pages': []}
with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True)
    context = browser.new_context(viewport={'width':1600,'height':1000}, timezone_id='UTC')
    context.add_init_script("if (location.origin === " + json.dumps(BASE) + ") { localStorage.setItem('apiKey','devkey123');localStorage.setItem('tenantId','default'); }")
    context.on('page', lambda p: p.on('pageerror', lambda e: result['errors'].append(str(e))))
    context.on('response', lambda r: result['http_errors'].append({'url':r.url,'status':r.status}) if r.status>=400 else None)
    page = context.new_page()
    page.set_default_timeout(15000)
    page.goto(BASE + '/', wait_until='networkidle')
    page.locator('#newButton').click()
    payload = json.dumps([{'title': 'Impossible travel ruled out. No credential dumping occurred.',
                          'status': 'closed', 'severity': 'info',
                          'createdDateTime': '2026-09-12T00:00:00Z', 'source_type': 'cloud'}])
    page.locator('#fileInput').set_input_files({'name': 'negative.json', 'mimeType': 'application/json',
                                               'buffer': payload.encode('utf-8-sig')})
    page.locator('#uploadForm button[type=submit]').click()
    expect(page.locator('#caseMeta')).to_contain_text('% processed', timeout=120000)
    from urllib.parse import urlsplit, parse_qs
    AID = parse_qs(urlsplit(page.url).query)['assessment'][0]
    result['assessment_id'] = AID
    expect(page.locator('#caseMeta')).to_contain_text('% processed', timeout=30000)
    selected = page.locator('#casePartitionSelector').input_value()
    api = context.request
    headers = {'x-api-key':'devkey123','x-tenant-id':'default'}
    view = api.get(BASE + f'/api/v1/assessments/{AID}/case-view?case_id={selected}', headers=headers).json()
    assert 'confirmed' not in page.locator('#breachSummary').inner_text().lower()
    assert view.get('evidence'), 'BOM-prefixed source row was lost'
    result['negative_input_preserved'] = True
    for label in ['Causal graph', 'Detailed timeline', 'Retrieval trace', 'Action plan', 'Evidence']:
        page.get_by_role('tab', name=label, exact=True).click()
    result['tabs_clicked'] = 5
    receipt = view['report_context']['historical_receipt']
    stamp = datetime.fromisoformat(receipt['recorded_at']).timestamp()
    cutoff = datetime.fromtimestamp(math.ceil(stamp*1000)/1000, timezone.utc).isoformat(timespec='milliseconds')
    page.locator('#knownAt').fill(cutoff.replace('+00:00','').rstrip('0').rstrip('.'))
    page.locator('#knownAt').dispatch_event('change')
    expect(page.locator('#caseMeta')).to_contain_text('Recorded view:', timeout=30000)
    historical_url = BASE + f'/api/v1/assessments/{AID}/case-view?case_id={selected}&as_known_at={cutoff.replace("+00:00","Z")}'
    historical = api.get(historical_url, headers=headers).json()
    assert historical['report_context']['historical_receipt']['receipt_hash'] == receipt['receipt_hash']
    assert historical['evidence'] == view['evidence']
    with page.expect_popup() as popup_info:
        page.locator('#exportGrcButton').click()
    popup = popup_info.value
    popup.wait_for_load_state()
    assert receipt['receipt_hash'] in popup.locator('body').inner_text()
    popup.screenshot(path=str(OUT/'release-historical-export.png'), full_page=True)
    popup.close()
    page.reload(wait_until='networkidle')
    expect(page.locator('#caseMeta')).to_contain_text('Recorded view:', timeout=30000)
    expect(page.locator('#caseMeta')).to_contain_text(receipt['recorded_at'])
    with page.expect_popup() as popup_info:
        page.locator('#exportGrcButton').click()
    popup = popup_info.value
    popup.wait_for_load_state()
    assert receipt['receipt_hash'] in popup.locator('body').inner_text()
    popup.close()
    assert page.locator('#casePartitionSelector').input_value() == selected
    result['historical_receipt'] = receipt
    page.screenshot(path=str(OUT/'release-historical-console.png'), full_page=True)
    page.locator('#knownAt').fill('2026-01-01T00:00')
    page.locator('#knownAt').dispatch_event('change')
    expect(page.locator('#caseMeta')).to_contain_text('Historical evidence only', timeout=30000)
    assert 'Evidence known at the selected time' in page.locator('#breachSummary').inner_text()
    page.set_viewport_size({'width':390,'height':844})
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    page.screenshot(path=str(OUT/'release-mobile.png'),full_page=True)
    page.set_viewport_size({'width':1600,'height':1000})
    for name in ['integrations','metrics','sbom','compliance','csv_multi_analyzer','hunt_network','hunt_endpoint','multi_log_investigator','investigate']:
        response = page.goto(BASE + '/static/' + name + '.html', wait_until='domcontentloaded')
        page.wait_for_timeout(800)
        assert response.status == 200
        result['pages'].append({'name':name, 'status':response.status})
    browser.close()
(OUT/'release-browser.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result,indent=2))
assert not result['errors'] and not result['http_errors']
