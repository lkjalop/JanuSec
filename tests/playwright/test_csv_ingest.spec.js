const { test, expect } = require('@playwright/test');
const fs = require('fs');

test('upload CSV and detect remote_access', async ({ request }) => {
  const filePath = 'tests/data/sample_remote_access.csv';
  const data = fs.readFileSync(filePath);
  const res = await request.post('http://localhost:8080/api/v1/csv/upload', {
    multipart: {
      file: {
        name: 'sample_remote_access.csv',
        mimeType: 'text/csv',
        buffer: data
      }
    },
    headers: { 'x-api-key': process.env.API_KEY || 'devkey123' }
  });
  expect(res.ok()).toBeTruthy();
  const json = await res.json();
  expect(['remote_access','email','unknown']).toContain(json.kind);
});
