const { test, expect } = require('@playwright/test');
const path = require('path');
const fs = require('fs');

const reports = [
  path.resolve(__dirname, '../../artifacts/reports/executive_review/azure/executive_report.html'),
  path.resolve(__dirname, '../../artifacts/reports/executive_review/aws/executive_report.html'),
];

for (const reportPath of reports) {
  const label = path.basename(path.dirname(reportPath));
  test(`Executive report layout renders: ${label}`, async ({ page }) => {
    if (!fs.existsSync(reportPath)) {
      test.skip(true, `Fixture not found: ${reportPath} — run a full report generation pass first`);
    }
    await page.goto(`file:///${reportPath.replace(/\\/g, '/')}`);
    await expect(page.getByText('Executive Report')).toBeVisible();
    await expect(page.getByText('Working Hypothesis')).toBeVisible();
    await expect(page.getByText('Report Metadata')).toBeVisible();
    await expect(page.getByText('Evidence Appendix')).toBeVisible();
    await expect(page.getByText('Key Evidence Reviewed')).toBeVisible();
    await expect(page.getByText('Immediate Decision Required')).toBeVisible();
  });
}
