"""Small Playwright acceptance for the canonical case workspace."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright


def run(base_url: str = "http://127.0.0.1:8081") -> dict:
    output = Path("dump/screenshots/new - pivot")
    output.mkdir(parents=True, exist_ok=True)
    console_errors: list[str] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        page.on("console", lambda message: console_errors.append(message.text) if message.type == "error" else None)
        page.goto(base_url, wait_until="networkidle")
        page.get_by_role("button", name="New assessment").first.click()
        page.locator("#dropZone").evaluate("""zone => {
          const transfer = new DataTransfer();
          transfer.items.add(new File(
            ['timestamp,user,action\\n2026-08-21T00:00:00Z,test@example.com,login'],
            'browser-drag-smoke.csv', {type: 'text/csv'}));
          zone.dispatchEvent(new DragEvent('dragenter', {bubbles: true, dataTransfer: transfer}));
          zone.dispatchEvent(new DragEvent('drop', {bubbles: true, dataTransfer: transfer}));
        }""")
        page.locator("#uploadPreflight").get_by_text("browser-drag-smoke.csv").wait_for()
        desktop = output / "acceptance-case-workspace-desktop.png"
        page.screenshot(path=str(desktop), full_page=True)
        desktop_text = page.locator("body").inner_text()
        desktop_result = {
            "drop_filename_visible": "browser-drag-smoke.csv" in desktop_text,
            "start_enabled": page.locator("#startAssessmentButton").is_enabled(),
            "what_you_get_visible": "One case workspace, with proof" in desktop_text,
            "screenshot": str(desktop.resolve()),
        }
        mobile_page = browser.new_page(viewport={"width": 390, "height": 844})
        mobile_page.goto(base_url, wait_until="networkidle")
        mobile_page.get_by_role("button", name="New assessment").first.click()
        mobile = output / "acceptance-case-workspace-mobile.png"
        mobile_page.screenshot(path=str(mobile), full_page=True)
        mobile_result = {
            "horizontal_overflow": mobile_page.evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth"),
            "upload_visible": mobile_page.locator("#dropZone").is_visible(),
            "screenshot": str(mobile.resolve()),
        }
        browser.close()
    return {"desktop": desktop_result, "mobile": mobile_result, "console_errors": console_errors}


if __name__ == "__main__":
    print(json.dumps(run(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8081"), indent=2))
