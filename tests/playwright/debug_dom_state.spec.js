const { test } = require('@playwright/test');

test('dump localStorage and element visibility', async ({ page }) => {
  await page.goto('http://localhost:8080/console');
  // Set adminKey for test then reload
  await page.evaluate(() => { localStorage.setItem('adminKey','test-admin-key'); localStorage.setItem('apiKey','devkey123'); });
  await page.reload();
  const adminKey = await page.evaluate(() => localStorage.getItem('adminKey'));
  const adminVisible = await page.evaluate(() => {
    const el = document.getElementById('adminTuningPanel');
    if(!el) return 'missing';
    const style = window.getComputedStyle(el);
    return { display: style.display, visible: style.display !== 'none' };
  });
  const tenantInputExists = await page.$('#tenantInput') !== null;
  console.log('adminKey:', adminKey);
  console.log('adminVisible:', adminVisible);
  console.log('tenantInputExists:', tenantInputExists);
});
