// Playwright test: verify HopGraph D3 visualization renders
// Assumes server running locally at http://localhost:8080

import { test, expect } from '@playwright/test';

test.describe('HopGraph Visualization', () => {
  test('renders SVG, legend, and nodes after explain call', async ({ page }) => {
    // Load page with a pre-set node query param (choose a likely existing node id stub)
    await page.goto('http://localhost:8080/static/graph_explain.html?node=host:myhost');
    // Ensure the page has an API key and trigger explain explicitly for CI determinism
    await page.evaluate(() => { localStorage.setItem('apiKey', 'devkey123'); });
    // Call runExplain in page context to ensure the fetch/render occurs under test control
    await page.evaluate(() => { try { runExplain(); } catch(e){ console.error('runExplain failed', e); } });

    // Wait for status to become either OK or Error (network completed)
    const statusEl = page.locator('#status');
    await expect(statusEl).toHaveText(/(OK|Error)/, { timeout: 10000 });

    // Capture API output text (kept for assertions) but avoid noisy logging in CI
    const outText = await page.locator('#output').textContent();
    if (outText && outText.includes('No chains found')) {
      throw new Error('API returned no chains: ' + outText);
    }

    // Wait for graph container to be rendered and SVG presence
    const container = page.locator('#graph-container');
    await expect(container).toBeVisible({ timeout: 15000 });
    // now assert the svg inside it
    const svgLocator = page.locator('#graph-container svg#graph-svg');
    await expect(svgLocator).toBeVisible({ timeout: 15000 });

    // Legend exists
    const legend = page.locator('#graph-container .legend');
    await expect(legend).toBeVisible();

    // At least one node circle (we expect the deterministic explain endpoint to provide nodes)
    // Try a few selector variants for robustness
    const nodeSelectors = [
      '#graph-container svg .node circle',
      '#graph-container svg circle.node',
      '#graph-container svg circle',
      '.node circle',
    ];
    let nodeCircles = null;
    let count = 0;
    for (const sel of nodeSelectors) {
      const loc = page.locator(sel);
      const c = await loc.count();
      if (c > 0) {
        nodeCircles = loc;
        count = c;
        break;
      }
    }
    if (!nodeCircles) {
      throw new Error('No node circles found with any selector variant');
    }
    expect(count).toBeGreaterThan(0);

    // Drag the first node a small amount and verify its position changes.
    const firstCircle = nodeCircles.nth(0);
    // Read initial transform/position (cx, cy) attributes if present, else read bounding box
    const getPos = async (el) => {
      const cx = await el.getAttribute('cx');
      const cy = await el.getAttribute('cy');
      if (cx !== null && cy !== null) {
        return { x: parseFloat(cx), y: parseFloat(cy) };
      }
      const box = await el.boundingBox();
      return { x: box.x + box.width / 2, y: box.y + box.height / 2 };
    };

    const before = await getPos(firstCircle);
    // Perform drag by mouse to offset +40, +30
    const svg = page.locator('#graph-container svg#graph-svg');
    const svgBox = await svg.boundingBox();
    if (!svgBox) throw new Error('SVG bounding box not available');
    // compute start absolute coords using element center to be robust
    // Convert SVG-local coordinates to page coordinates using the SVG bounding box
    const startX = svgBox.x + before.x;
    const startY = svgBox.y + before.y;
    // move slowly with steps to emulate user drag
    await page.mouse.move(startX, startY, { steps: 5 });
    await page.mouse.down();
    await page.mouse.move(startX + 48, startY + 36, { steps: 12 });
    await page.mouse.up();
    // allow simulation tick and stabilization
    await page.waitForTimeout(750);
    const after = await getPos(firstCircle);
    // position should have changed by at least a few pixels
    const dx = Math.abs(after.x - before.x);
    const dy = Math.abs(after.y - before.y);
    expect(dx + dy).toBeGreaterThan(5);

    // Toggle JSON panel (try multiple toggle selectors and panel selectors)
    const toggleSelectors = ['#toggle-json', '.json-toggle', 'button:has-text("JSON")'];
    const panelSelectors = ['#json-panel', '.json-panel', '#details-json'];
    let toggleFound = null;
    for (const t of toggleSelectors) {
      const loc = page.locator(t);
      if (await loc.count() > 0) {
        toggleFound = loc;
        break;
      }
    }
    if (toggleFound) {
      // find a panel
      let panelFound = null;
      for (const p of panelSelectors) {
        const pl = page.locator(p);
        if (await pl.count() > 0) {
          panelFound = pl;
          break;
        }
      }
      if (panelFound) {
        await toggleFound.click();
        await expect(panelFound).toBeVisible();
        await toggleFound.click();
        await expect(panelFound).not.toBeVisible();
      } else {
        console.warn('JSON toggle present but no panel selector matched; skipping panel visibility asserts');
      }
    } else {
      console.warn('No JSON toggle control found; skipping JSON panel assertions');
    }
  });
});
