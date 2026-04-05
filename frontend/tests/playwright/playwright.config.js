const { defineConfig } = require('@playwright/test');
module.exports = defineConfig({
  testDir: './',
  timeout: 30_000,
  use: { headless: true, baseURL: 'http://localhost:8080' }
});
