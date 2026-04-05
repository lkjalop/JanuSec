// Temporary Playwright config used by the test runner to avoid starting the webserver
const base = require('./playwright.config.js');
module.exports = Object.assign({}, base, { webServer: undefined, projects: [ { name: 'chromium', use: { viewport: { width: 1280, height: 800 }, headless: true } } ] });
