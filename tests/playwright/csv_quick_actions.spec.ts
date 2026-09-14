import { test, expect } from '@playwright/test';

test.describe('CSV Multi-Analyzer Quick Actions', () => {
  test('Build session then Create Incident, Export Report, Send to SIEM', async ({ page }) => {
    // Set API key and navigate
    await page.addInitScript(() => {
      try { localStorage.setItem('apiKey', 'devkey123'); } catch {}
    });
    await page.goto('http://localhost:8080/static/csv_multi_analyzer.html');

    // Upload a tiny CSV from fixture
    const csvContent = 'user,host,process,sha256,domain\n' +
      'alice,host1,rundll32,deadbeef,api.example.com\n' +
      'bob,host2,regsvr32,beadfeed,mail.example.com\n';
    await page.setInputFiles('#fileInput', {
      name: 'mini.csv',
      mimeType: 'text/csv',
      buffer: Buffer.from(csvContent)
    });
    await page.evaluate(() => { try { window.__forceCsvMultiMapping && window.__forceCsvMultiMapping(); } catch(e) {} });
    // Wait until Build button becomes enabled after file parse
    await page.waitForFunction(() => {
      const btn = document.querySelector('#btnBuildGraph') as HTMLButtonElement | null;
      return !!btn && !btn.disabled;
    });

    // Click Build HopGraph
    const buildBtn = page.locator('#btnBuildGraph');
    await expect(buildBtn).toBeEnabled();
    await buildBtn.click();

    // Wait for summary panel to show and confidence metric render
    await page.waitForSelector('#summaryPanel', { state: 'visible' });
    await page.waitForSelector('#metricGrid .metric:has-text("Confidence")');

    // Click Create Incident and expect a banner message
    const createBtn = page.locator('#btnCreateIncident');
    await createBtn.click();
    // The page uses pushWarn to append to #uploadErrors; check for confirmation text
    await expect(page.locator('#uploadErrors .warn-line').last()).toContainText(/Incident created|Auto-incident generated/);

    // Click Export Report and expect new page to open or blob URL created
    const [newPage] = await Promise.all([
      page.context().waitForEvent('page'),
      page.locator('#btnExportReport').click()
    ]);
    await newPage.waitForLoadState('domcontentloaded');
    // Basic HTML check
    const content = await newPage.content();
    expect(content).toMatch(/<html|<body|Investigation/i);

    // Click Send to SIEM and expect toast/warn-line
    await page.locator('#btnSendToSiem').click();
    await expect(page.locator('#uploadErrors .warn-line').last()).toContainText(/Sent test notification|Webhook/);
  });
});
