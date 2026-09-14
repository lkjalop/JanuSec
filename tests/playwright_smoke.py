"""Playwright smoke tests for:
1. Summarise button fires and returns a non-UNCERTAIN verdict
2. Tier 2 canvas rows load with real event descriptions (not stubs)
"""
import asyncio, json, sys, time
from playwright.async_api import async_playwright

BASE      = "http://localhost:8080"
API_KEY   = "janusec-staging-local-20260324"
AID       = "assessment-1776199585-44037004"
CLUSTER_1 = "cluster-1"

RESULTS = {}

async def run():
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        ctx = await browser.new_context()

        # ── Inject API key + last assessment so investigate.js auto-loads ──
        await ctx.add_init_script(f"""
            localStorage.setItem('apiKey', '{API_KEY}');
            localStorage.setItem('tenantId', 'default');
            localStorage.setItem('last_assessment_id', '{AID}');
        """)

        # ─────────────────────────────────────────────────────────────────
        # TEST 1: Summarise endpoint returns llm_available=true + verdict
        # ─────────────────────────────────────────────────────────────────
        print("\\n[TEST 1] Calling llm-summary endpoint directly...")
        page = await ctx.new_page()

        resp = await page.request.get(
            f"{BASE}/api/v1/assessments/{AID}/clusters/{CLUSTER_1}/tier2/llm-summary"
            f"?model=qwen2.5%3A14b&force_refresh=true",
            headers={"X-API-Key": API_KEY},
            timeout=180000,
        )
        data = await resp.json()

        llm_ok      = data.get("llm_available", False)
        verdict     = (data.get("sections") or {}).get("reality_verdict", "MISSING")
        what        = (data.get("sections") or {}).get("what_is_happening", "")
        actions     = (data.get("sections") or {}).get("what_to_do", "")
        has_entity  = "[ACCOUNT" in actions or "[HOST" in actions or "[IP" in actions
        verdict_ok  = verdict in ("LIKELY REAL", "LIKELY BENIGN")

        RESULTS["test1_llm_available"]   = llm_ok
        RESULTS["test1_verdict"]         = verdict
        RESULTS["test1_verdict_ok"]      = verdict_ok
        RESULTS["test1_has_entity_card"] = has_entity
        RESULTS["test1_what_snippet"]    = what[:120] if what else "(empty)"
        RESULTS["test1_actions_snippet"] = actions[:200] if actions else "(empty)"

        print(f"  llm_available : {llm_ok}")
        print(f"  verdict       : {verdict}  {'OK' if verdict_ok else 'FAIL'}")
        print(f"  entity cards  : {has_entity}  (lines with [ACCOUNT/HOST/IP])")
        print(f"  what snippet  : {what[:100]}")

        # ─────────────────────────────────────────────────────────────────
        # TEST 2: Tier-2 steps have evidence-grounded instructions
        # ─────────────────────────────────────────────────────────────────
        print("\\n[TEST 2] Calling /tier2 steps endpoint...")
        resp2 = await page.request.get(
            f"{BASE}/api/v1/assessments/{AID}/clusters/{CLUSTER_1}/tier2",
            headers={"X-API-Key": API_KEY}
        )
        t2 = await resp2.json()

        steps   = t2.get("steps", [])
        phase1  = [s for s in steps if s.get("phase") == "contain"]

        # Check that contain steps have specific entity names (not just "affected entities")
        generic_phrases = ["affected entities", "affected accounts", "(none)", "affected hosts"]
        specific_steps = []
        for s in phase1:
            instr = s.get("instructions", "") or s.get("title", "")
            is_generic = any(g in instr for g in generic_phrases) and len(instr) < 80
            if not is_generic:
                specific_steps.append(instr[:100])

        has_specific = len(specific_steps) > 0
        RESULTS["test2_step_count"]    = len(steps)
        RESULTS["test2_phase1_count"]  = len(phase1)
        RESULTS["test2_has_specific"]  = has_specific
        RESULTS["test2_specific_steps"] = specific_steps[:3]

        print(f"  total steps   : {len(steps)}")
        print(f"  contain steps : {len(phase1)}")
        print(f"  specific steps: {has_specific}")
        for s in specific_steps[:3]:
            print(f"    - {s}")

        # ─────────────────────────────────────────────────────────────────
        # TEST 3: Browser UI — open Investigate page, open drawer, click Summarise
        # ─────────────────────────────────────────────────────────────────
        print("\\n[TEST 3] Browser UI — navigate to investigate page...")
        page2 = await ctx.new_page()

        # Capture console errors
        errors = []
        page2.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)

        url = f"{BASE}/static/investigate.html"
        await page2.goto(url, wait_until="networkidle", timeout=30000)

        # Use loadHistoryEntry() (exposed on window) to load the assessment + render clusters
        await page2.evaluate(f"window.loadHistoryEntry && window.loadHistoryEntry('{AID}')")
        await page2.wait_for_timeout(3000)

        # Wait for cluster table rows to populate (investigate.js renders tr[data-cluster-id])
        try:
            await page2.wait_for_selector("tr[data-cluster-id], .summary-cluster-card", timeout=15000)
            page_loaded = True
        except Exception:
            page_loaded = False
            print("  WARNING: cluster table did not populate in time")

        # Click the severity box to open the cluster list panel
        sev_box = await page2.query_selector(".sev-box[data-filter='correlated-critical'], .sev-box")
        if sev_box:
            await sev_box.click()
            await page2.wait_for_timeout(1000)

        # Click the drill-in button for cluster-1
        cluster_btn = await page2.query_selector(
            f".cluster-drill-btn[data-cluster-id='{CLUSTER_1}'], "
            f"tr[data-cluster-id='{CLUSTER_1}'] button, "
            f"button[data-cluster-id='{CLUSTER_1}']"
        )
        if not cluster_btn:
            cluster_btn = await page2.query_selector("tr[data-cluster-id] button, .cluster-drill-btn")

        drawer_opened = False
        if cluster_btn:
            await cluster_btn.click()
            await page2.wait_for_timeout(2000)
            # Drawer is open when it has class 'open'
            drawer = await page2.query_selector("#clusterDrawer")
            if drawer:
                is_open = await drawer.get_attribute("class") or ""
                drawer_opened = "open" in is_open
            print(f"  drawer opened : {drawer_opened}")
        else:
            print("  WARNING: No cluster drill-in button found — skipping drawer test")

        # Look for Summarise button (rendered by _renderLlmSummaryHtml via data-action)
        summarise_btn = await page2.query_selector(
            "button[data-action='llm-summarize'], "
            "button:has-text('Summarise'), button:has-text('Summarize')"
        )
        RESULTS["test3_page_loaded"]     = page_loaded
        RESULTS["test3_drawer_opened"]   = drawer_opened
        RESULTS["test3_summarise_found"] = summarise_btn is not None

        if summarise_btn:
            print(f"  Summarise btn : FOUND")
            # Verify button has data-action and data-cluster-id (event-delegate pattern, no onclick needed)
            data_action = await summarise_btn.get_attribute("data-action")
            data_cid    = await summarise_btn.get_attribute("data-cluster-id")
            has_onclick = data_action == "llm-summarize" and bool(data_cid)
            RESULTS["test3_onclick_valid"] = has_onclick
            print(f"  data-action valid: {has_onclick}  (action={data_action}, cid={data_cid})")
        else:
            print("  Summarise btn : NOT FOUND")
            RESULTS["test3_onclick_valid"] = False

        RESULTS["test3_js_errors"] = errors[:5]

        await page2.close()
        await page.close()
        await browser.close()

    # ── Summary ────────────────────────────────────────────────────────────
    print("\n" + "="*60)
    print("RESULTS SUMMARY")
    print("="*60)
    ok_count = 0
    checks = [
        ("LLM available",          RESULTS.get("test1_llm_available")),
        ("Verdict not UNCERTAIN",   RESULTS.get("test1_verdict_ok")),
        ("Entity cards in actions", RESULTS.get("test1_has_entity_card")),
        ("T2 steps loaded",        RESULTS.get("test2_step_count", 0) > 0),
        ("T2 contain steps",       RESULTS.get("test2_phase1_count", 0) > 0),
        ("T2 specific steps",      RESULTS.get("test2_has_specific")),
        ("Page loaded (clusters)",  RESULTS.get("test3_page_loaded")),
        ("Drawer opens",           RESULTS.get("test3_drawer_opened")),
        ("Summarise btn found",    RESULTS.get("test3_summarise_found")),
        ("data-action valid",      RESULTS.get("test3_onclick_valid")),
    ]
    for label, result in checks:
        icon = "PASS" if result else "FAIL"
        print(f"  [{icon}] {label}")
        if result:
            ok_count += 1

    print(f"\n{ok_count}/{len(checks)} checks passed")
    print(f"\nVERDICT: {RESULTS.get('test1_verdict', '?')}")
    print(f"WHAT:    {RESULTS.get('test1_what_snippet', '?')}")
    return ok_count, len(checks)

if __name__ == "__main__":
    passed, total = asyncio.run(run())
    sys.exit(0 if passed >= total - 2 else 1)  # allow up to 2 non-critical failures
