"""Real Chromium checks against a restored loopback pilot; never logs its keys."""
import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright, expect


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--port', type=int, default=8443)
    parser.add_argument('--credential', type=Path, help='Private named credential file instead of bootstrap access')
    args = parser.parse_args()
    values = json.loads((args.state / 'secrets.json').read_text(encoding='utf-8'))
    entry = json.loads(values['API_KEYS_JSON'])[0]
    if args.credential:
        entry = json.loads(args.credential.read_text(encoding='utf-8'))
    baseline = json.loads(args.baseline.read_text(encoding='utf-8'))
    base = f'https://127.0.0.1:{args.port}'
    result = {'errors': [], 'http_errors': [], 'tabs': [], 'mocked_routes': False,
              'browser_certificate_exception': 'generated localhost certificate only; API TLS verified separately'}
    args.output.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True, viewport={'width': 1600, 'height': 1000}, timezone_id='UTC')
        context.add_init_script('if (location.origin === ' + json.dumps(base) + ') {'
                                'localStorage.setItem("apiKey",' + json.dumps(entry['key']) + ');'
                                'localStorage.setItem("tenantId",' + json.dumps(entry['tenant_id']) + ');}')
        page = context.new_page()
        page.on('pageerror', lambda error: result['errors'].append(str(error)))
        context.on('response', lambda response: result['http_errors'].append(
            {'path': urlsplit(response.url).path, 'status': response.status}) if response.status >= 400 else None)
        page.goto(base + '/?assessment=' + baseline['assessment_id'], wait_until='domcontentloaded')
        expect(page.locator('#caseMeta')).to_contain_text('100% processed', timeout=90000)
        page.locator('#casePartitionSelector').select_option(baseline['selected_case'])
        expect(page.locator('#caseTitle')).to_have_text(baseline['selected_case'])
        for tab in ('Causal graph', 'Detailed timeline', 'Retrieval trace', 'Action plan', 'Evidence'):
            page.get_by_role('tab', name=tab, exact=True).click()
            result['tabs'].append(tab)
        page.locator('[data-evidence]').first.click()
        expect(page.locator('#inspectorContent')).to_contain_text('evidence')
        result['evidence_drilldown'] = True
        with page.expect_popup() as popup:
            page.locator('#exportGrcButton').click()
        popup.value.wait_for_load_state()
        assert baseline['assessment_id'] in popup.value.locator('body').inner_text()
        popup.value.close()
        result['authenticated_export'] = True
        page.screenshot(path=str(args.output / 'restored-desktop.png'), full_page=True)
        page.set_viewport_size({'width': 390, 'height': 844})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        page.screenshot(path=str(args.output / 'restored-mobile.png'), full_page=True)
        page.reload(wait_until='domcontentloaded')
        expect(page.locator('#caseMeta')).to_contain_text('100% processed', timeout=90000)
        result['mobile_and_reload'] = True
        assert not result['errors'] and not result['http_errors'], result
        result['passed'] = True
        browser.close()
    (args.output / 'browser.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
