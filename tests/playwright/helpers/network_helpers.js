/**
 * Centralized Playwright network helper mocks used by CSV tests.
 * Provides reusable route handlers for upload and pipeline analyze endpoints.
 */
module.exports = {
  /**
   * Mock /api/v1/upload/files to return a deterministic payload and optionally inject rows into the page.
   * payloadRows: array of normalized rows (process_name, file_path, hash, host, verdict, raw)
   */
  async mockUploadAndInject(page, payloadRows){
    await page.route('**/api/v1/upload/files', async route => {
      const response = { status: 'completed', files_processed: 1, total_size: 0, results: [{ filename: 'mock.csv', size: 0 }], rows: payloadRows };
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(response) });
    });
    // Optional injection: after route is set, tests can choose to call
    // page.evaluate(() => window.ensureTbodyRowsFromList(window.LAST_RESULTS || []))
  },

  /**
   * Mock pipeline analyze endpoint to return a deep-enrichment artifact
   * that tests can use to assert UI merge behavior.
   * artifactResponse is an object returned as JSON.
   */
  async mockAnalyzeBatch(page, artifactResponse){
    await page.route('**/api/v1/artifacts/analyze_batch', async route => {
      const body = artifactResponse || { report: { all_artifacts: [] } };
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
    });
  }
};
