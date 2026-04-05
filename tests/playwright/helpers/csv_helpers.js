const path = require('path');

/**
 * Helper utilities for CSV Playwright tests.
 */
module.exports = {
  dataTest: (name) => `[data-test="${name}"]`,

  async getFileInput(page){
    // Prefer data-test attribute, fallback to id
    let el = await page.$(module.exports.dataTest('csv-file-input'));
    if(el) return el;
    el = await page.$('input[type=file]#fileInput');
    return el;
  },

  async clickWithFallback(page, dataTestName, oldSelector){
    const dt = module.exports.dataTest(dataTestName);
    try{
      const locator = page.locator(dt);
      if(await locator.count() > 0){
        await locator.click();
        return true;
      }
    }catch(e){}
    try{ await page.click(oldSelector); return true; }catch(e){ return false; }
  },

  async waitForCsvReady(page, timeout=5000){
    // Wait for explicit readiness marker or legacy id
    try{
      await page.waitForSelector(module.exports.dataTest('csv-results-ready'), { timeout });
      return true;
    }catch(e){ /* fallback */ }
    try{ await page.waitForSelector('#csv_results_ready', { timeout }); return true; }catch(e){ /* fallback */ }
    // last resort: small timeout
    await page.waitForTimeout(300);
    return false;
  },

  async setInputFilesSafe(page, file){
    const input = await module.exports.getFileInput(page);
    if(!input) throw new Error('No file input found');
    await input.setInputFiles(file);
  }
  ,
  // Navigate to the canonical CSV analyzer, prefer test shim when enabled
  async gotoCsvAnalyzer(page){
    const useShim = !!process.env.PLAYWRIGHT_USE_TEST_SHIM || !!process.env.TEST_SHIM;
    if(useShim){
      await page.goto('/static/test_shims/csv_analyzer_shim.html', { waitUntil: 'load' });
      return;
    }
    await page.goto('/static/csv_analyzer.html', { waitUntil: 'load' });
  }
};
