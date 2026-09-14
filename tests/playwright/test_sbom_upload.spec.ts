import { test, expect } from '@playwright/test';

test.describe('SBOM upload smoke', () => {
  test('upload example SBOM and show vulns', async ({ page }) => {
    // Use the local demo key (page provides banner button which sets localStorage)
    await page.goto('http://localhost:8080/static/sbom.html');

    // If auth banner present, click Use demo key
    const useDemo = await page.locator('#setDemoKey');
    if (await useDemo.count() > 0) {
      await useDemo.click();
      // wait a short moment for reload
      await page.waitForTimeout(800);
      await page.goto('http://localhost:8080/static/sbom.html');
    }

    // Ensure textarea: accept prefilled (dev helper) or click Use Example if empty
    const ta = page.locator('#sbom');
    const taCount = await ta.count();
    if(taCount > 0){
      const val = await ta.inputValue();
      if(!val || val.trim()===''){
        const useBtn = page.locator('#useExampleSbom');
        await expect(useBtn).toBeVisible();
        await useBtn.click();
      }
    }

    // Click Upload
    const upload = page.locator('#btnUpload');
    await expect(upload).toBeVisible();
    await upload.click();

    // Wait for either a toast or the vulnerabilities table to populate
    // Check for the table rows (except header)
    const rows = page.locator('#tbl tbody tr');
    await page.waitForTimeout(1000);

    // Accept either: at least one vuln row OR a toast contains 'SBOM uploaded'
    const toast = page.locator('#toast');
    const hasRows = (await rows.count()) > 0;
    const toastText = (await toast.count()) ? await toast.innerText() : '';

    expect(hasRows || /SBOM uploaded/i.test(toastText)).toBeTruthy();
  });
});
