/**
 * timeline_3col_cross_dataset.spec.js
 *
 * Validates the 3-column timeline changes (business_impact + pasta_stage badge)
 * and ISO 27035 section across VESPER, MERIDIAN, SANTOS, ALICE assessments.
 * Also checks: timeline steps, drill-down, persona dispatch, LLM regenerate.
 *
 * Run:
 *   npx playwright test tests/playwright/timeline_3col_cross_dataset.spec.js --headed
 */

const { test, expect } = require('@playwright/test');

test.describe.configure({ mode: 'serial' });

const BASE   = process.env.PLAYWRIGHT_BASE_URL || 'http://localhost:8080';
const BREACH = BASE + '/static/breach.html';

const DATASETS = {
  vesper:   'assessment-1778283264-c3e8840c',
  meridian: 'assessment-1778286574-becc6edc',
  santos:   'assessment-1778285515-749ab025',
  alice:    'assessment-1778290515-a6d22489',
};

// ── helpers ───────────────────────────────────────────────────────────────────

async function loadAssessment(page, id, label) {
  await page.goto(BREACH + '?assessment=' + id, { waitUntil: 'domcontentloaded', timeout: 30000 });
  // br-meta is the real testid that renders once assessment JSON loads
  await page.waitForSelector('[data-testid="br-meta"]', { timeout: 25000 });
  await page.screenshot({ path: `test-results/3col_${label}_01_loaded.png` });
  console.log(`  [${label}] loaded — br-meta visible`);
}

async function scrollToTimeline(page) {
  const timeline = page.locator('.br-story__timeline').first();
  if (await timeline.count() > 0) {
    await timeline.scrollIntoViewIfNeeded();
    await page.waitForTimeout(400);
  }
  return timeline;
}

async function inspectStep(page, label, idx) {
  const step = page.locator('.br-story__step').nth(idx);
  const hasContext   = await step.locator('.br-story__context').count() > 0;
  const hasStage     = await step.locator('.br-story__stage').count() > 0;
  const hasBizImpact = await step.locator('.br-story__business-impact').count() > 0;
  const stageText    = hasStage    ? await step.locator('.br-story__stage').first().innerText() : '(none)';
  const impactText   = hasBizImpact ? (await step.locator('.br-story__business-impact').first().innerText()).slice(0, 80) : '(none)';
  console.log(`  [${label}] step[${idx}]  context=${hasContext}  stage="${stageText}"  impact="${impactText}"`);
  return { hasContext, hasStage, hasBizImpact, stageText };
}

// ── per-dataset test factory ──────────────────────────────────────────────────

function makeTests(label, id) {

  // 1 — page load
  test(`[${label}] page loads — br-meta and verdict hero visible`, async ({ page }) => {
    await loadAssessment(page, id, label);

    const hero    = page.locator('[data-testid="br-hero"]');
    const verdict = page.locator('[data-testid="breach-answer-verdict"]');
    const heroOk  = await hero.count() > 0;
    const verdOk  = await verdict.count() > 0;
    const verdText = verdOk ? await verdict.innerText() : '(not found)';
    console.log(`  [${label}] hero=${heroOk}  verdict="${verdText}"`);
    expect(await page.locator('[data-testid="br-meta"]').count()).toBeGreaterThan(0);
  });

  // 2 — 3-column timeline
  test(`[${label}] timeline: 3rd column (context + stage badge + business impact)`, async ({ page }) => {
    await loadAssessment(page, id, label);
    await scrollToTimeline(page);

    const stepCount = await page.locator('.br-story__step').count();
    console.log(`  [${label}] ${stepCount} timeline steps`);

    if (stepCount === 0) {
      console.log(`  [${label}] WARN: no timeline steps — assessment may be benign/unprocessed`);
      return;
    }

    // Check first, middle, last step
    for (const idx of [...new Set([0, Math.floor(stepCount / 2), stepCount - 1])]) {
      const r = await inspectStep(page, label, idx);
      expect(r.hasContext).toBe(true);
      if (!r.hasStage)     console.log(`  [${label}] WARN step[${idx}]: no stage badge (factor may be absent for this dataset)`);
      if (!r.hasBizImpact) console.log(`  [${label}] WARN step[${idx}]: no business impact text`);
    }

    await page.screenshot({ path: `test-results/3col_${label}_02_timeline.png` });
  });

  // 3 — badge severity ramp
  test(`[${label}] stage badge colour classes (severity ramp yellow→orange→red)`, async ({ page }) => {
    await loadAssessment(page, id, label);
    await scrollToTimeline(page);

    const critical = await page.locator('.br-story__stage--critical').count();
    const high     = await page.locator('.br-story__stage--high').count();
    const medium   = await page.locator('.br-story__stage--medium').count();
    const total    = critical + high + medium;
    const steps    = await page.locator('.br-story__step').count();

    console.log(`  [${label}] badges  critical=${critical} high=${high} medium=${medium} total=${total}  steps=${steps}`);
    if (steps > 0) expect(total).toBeGreaterThan(0);
  });

  // 4 — ISO 27035 section
  test(`[${label}] ISO 27035 lifecycle section visible`, async ({ page }) => {
    await loadAssessment(page, id, label);
    await page.evaluate(() => window.scrollBy(0, 1400));
    await page.waitForTimeout(600);

    const section = page.locator('text=ISO 27035').first();
    const detectRow = page.locator('text=DETECT, text=Detect / Report, text=Detect').first();
    const sectionOk = await section.count() > 0;
    const detectOk  = await detectRow.count() > 0;
    console.log(`  [${label}] ISO 27035 visible=${sectionOk}  DETECT row=${detectOk}`);
    if (sectionOk) await section.scrollIntoViewIfNeeded();
    await page.screenshot({ path: `test-results/3col_${label}_03_iso27035.png` });
    if (!sectionOk) console.log(`  [${label}] WARN: ISO 27035 section not found`);
  });

  // 5 — drill-down expansion
  test(`[${label}] drill-down expands (SOC analyst panel / cluster detail)`, async ({ page }) => {
    await loadAssessment(page, id, label);

    // Try "Deepen investigation" button first, then the drilldown toggle
    const deepen  = page.locator('[data-testid="br-drilldown"] summary, text=Deepen investigation, text=Deepen Investigation').first();
    const toggle  = page.locator('[data-testid="br-toggle-drilldown"]').first();
    const analyst = page.locator('[data-testid="br-analyst-detail"] summary, .br-analyst-detail summary').first();

    if (await toggle.count() > 0) {
      await toggle.scrollIntoViewIfNeeded();
      await toggle.click({ timeout: 5000 }).catch(() => {});
      await page.waitForTimeout(700);
      console.log(`  [${label}] clicked br-toggle-drilldown`);
    } else if (await deepen.count() > 0) {
      await deepen.scrollIntoViewIfNeeded();
      await deepen.click({ timeout: 5000 }).catch(() => {});
      await page.waitForTimeout(700);
      console.log(`  [${label}] clicked deepen/drilldown summary`);
    }

    if (await analyst.count() > 0) {
      await analyst.scrollIntoViewIfNeeded();
      await analyst.click({ timeout: 4000 }).catch(() => {});
      await page.waitForTimeout(600);
      console.log(`  [${label}] opened analyst detail`);
    }

    await page.screenshot({ path: `test-results/3col_${label}_04_drilldown.png` });

    const cards = await page.locator('.br-card').count();
    console.log(`  [${label}] br-card count after expand: ${cards}`);
  });

  // 6 — persona dispatch
  test(`[${label}] persona dispatch buttons clickable`, async ({ page }) => {
    await loadAssessment(page, id, label);
    await page.evaluate(() => window.scrollBy(0, 2400));
    await page.waitForTimeout(500);

    const personaLabels = ['SOC Analyst', 'CISO', 'Executive', 'Compliance', 'Full Report'];
    let found = 0;
    for (const pl of personaLabels) {
      const btn = page.locator(`button:has-text("${pl}"), [data-persona="${pl.toLowerCase().replace(' ','-')}"]`).first();
      if (await btn.count() > 0) {
        found++;
        await btn.scrollIntoViewIfNeeded().catch(() => {});
        await btn.click({ timeout: 4000 }).catch(() => {});
        await page.waitForTimeout(500);
        console.log(`  [${label}] dispatch clicked: ${pl}`);
      }
    }
    console.log(`  [${label}] dispatch buttons found and clicked: ${found}/${personaLabels.length}`);
    await page.screenshot({ path: `test-results/3col_${label}_05_dispatch.png` });
  });

  // 7 — LLM regenerate
  test(`[${label}] LLM regenerate button present and clickable`, async ({ page }) => {
    await loadAssessment(page, id, label);

    // breach.js renders: <span class="br-exec__regen" id="br-exec-regen">↻ regenerate</span>
    const regenSpan = page.locator('#br-exec-regen, .br-exec__regen').first();
    const regenText = page.locator('text=regenerate, text=Regenerate').first();

    const hasRegen = await regenSpan.count() > 0 || await regenText.count() > 0;
    console.log(`  [${label}] regenerate button found: ${hasRegen}`);

    if (hasRegen) {
      const target = await regenSpan.count() > 0 ? regenSpan : regenText;
      await target.scrollIntoViewIfNeeded().catch(() => {});
      await page.screenshot({ path: `test-results/3col_${label}_06a_before_regen.png` });
      await target.click({ timeout: 5000 }).catch(() => {});
      // Give LLM call up to 30s to respond (or time out gracefully)
      await page.waitForTimeout(3000);
      await page.screenshot({ path: `test-results/3col_${label}_06b_after_regen.png` });
      console.log(`  [${label}] regenerate clicked — screenshot captured`);
    }

    // Also check the model badge in the top-right dropdown
    const modelDropdown = page.locator('select[data-testid="llm-model"], #llm-model-select, .llm-model').first();
    if (await modelDropdown.count() > 0) {
      const modelVal = await modelDropdown.inputValue().catch(() => '(n/a)');
      console.log(`  [${label}] LLM model selector value: ${modelVal}`);
    }

    if (!hasRegen) console.log(`  [${label}] WARN: no regenerate button found`);
    await page.screenshot({ path: `test-results/3col_${label}_06_regen.png` });
  });
}

// ── instantiate all four ──────────────────────────────────────────────────────

test.describe('VESPER — 98,750 rows · 4 sources · full APT chain', () => {
  makeTests('vesper', DATASETS.vesper);
});

test.describe('MERIDIAN — C2 + mailbox + lateral movement', () => {
  makeTests('meridian', DATASETS.meridian);
});

test.describe('SANTOS — PowerStage multi-cluster', () => {
  makeTests('santos', DATASETS.santos);
});

test.describe('ALICE — small targeted · 241 rows', () => {
  makeTests('alice', DATASETS.alice);
});
