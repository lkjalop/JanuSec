"""Headless clickthrough for the canonical case workspace."""

from __future__ import annotations

import argparse
import json
import threading
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import sync_playwright


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8081")
    parser.add_argument("--dataset")
    parser.add_argument("--assessment-id")
    parser.add_argument("--tenant-id", default="default")
    parser.add_argument("--fixture", help="Serve this CaseEvidenceViewModel JSON for deterministic UI checks")
    parser.add_argument("--viewport", choices=("desktop", "mobile"), default="desktop")
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    args = parser.parse_args()

    if not args.dataset and not args.assessment_id and not args.fixture:
        parser.error("--dataset, --assessment-id, or --fixture is required")
    dataset = Path(args.dataset).resolve(strict=True) if args.dataset else None
    files = (
        [str(path) for path in sorted(dataset.iterdir()) if path.is_file() and path.suffix.lower() != ".md"]
        if dataset
        else []
    )
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    fixture = Path(args.fixture).resolve(strict=True) if args.fixture else None
    fixture_view = json.loads(fixture.read_text(encoding="utf-8")) if fixture else None
    assessment_id = args.assessment_id or ((fixture_view or {}).get("case") or {}).get("id")
    label = dataset.name if dataset else (fixture.stem if fixture else assessment_id)
    result = {"dataset": label, "files": len(files), "started_at": time.time(), "tabs": {}}

    fixture_server = None
    base_url = args.base_url
    if fixture_view:
        static_root = Path(__file__).resolve().parents[1] / "frontend"
        handler = partial(SimpleHTTPRequestHandler, directory=str(static_root))
        fixture_server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=fixture_server.serve_forever, daemon=True).start()
        base_url = (
            f"http://127.0.0.1:{fixture_server.server_port}"
            "/static/janusec-platform-complete-LIVE.html"
        )

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        viewport = {"width": 390, "height": 844} if args.viewport == "mobile" else {"width": 1600, "height": 1000}
        page = browser.new_page(viewport=viewport)
        page_errors: list[str] = []
        page.on("pageerror", lambda error: page_errors.append(str(error)))
        if fixture_view:
            fixture_case = fixture_view.get("case") or {}
            page.route(
                "**/api/v1/model-providers",
                lambda route: route.fulfill(json={"providers": [{"provider": "deterministic", "available": True, "models": ["janusec-rules"]}]}),
            )
            page.route(
                f"**/api/v1/assessments/{assessment_id}/case-view*",
                lambda route: route.fulfill(json=fixture_view),
            )
            page.route(
                f"**/api/v1/assessments/{assessment_id}/cases",
                lambda route: route.fulfill(
                    json={
                        "assessment_id": assessment_id,
                        "cases": [
                            {
                                "case_id": fixture_case.get("id", assessment_id),
                                "title": fixture_case.get("title", "Fixture case"),
                                "status": "active",
                                "verdict": fixture_case.get("verdict", "suspected"),
                            }
                        ],
                    }
                ),
            )
        separator = "&" if "?" in base_url else "?"
        target_url = base_url + (f"{separator}assessment={assessment_id}" if assessment_id else "")
        page.goto(target_url, wait_until="networkidle")
        page.evaluate(
            "([apiKey, tenantId]) => { localStorage.setItem('apiKey', apiKey); localStorage.setItem('tenantId', tenantId); }",
            ["devkey123", args.tenant_id],
        )
        page.reload(wait_until="networkidle")
        result["title"] = page.title()
        result["inbox_visible"] = page.locator("#inboxView").is_visible()
        if files:
            page.locator("#newButton").click()
            page.locator("#fileInput").set_input_files(files)
            page.locator("#uploadForm button[type=submit]").click()
        deadline = time.time() + args.timeout_seconds
        while time.time() < deadline:
            if page.locator("#caseView").is_visible():
                visible_case_id = page.locator("#caseTitle").inner_text().strip()
                case_meta = page.locator("#caseMeta").inner_text().strip()
                if visible_case_id and "Loading authoritative" not in case_meta:
                    if assessment_id is None:
                        assessment_id = visible_case_id
                    break
            if "failed" in page.locator("#progressText").inner_text().lower():
                break
            page.wait_for_timeout(1500)
        result["case_visible"] = page.locator("#caseView").is_visible()
        result["case_id"] = page.locator("#caseTitle").inner_text()
        result["assessment_id"] = parse_qs(urlsplit(page.url).query).get("assessment", [assessment_id])[0]
        result["case_meta"] = page.locator("#caseMeta").inner_text()
        result["case_partition_selector_visible"] = page.locator("#casePartitionSelector").is_visible()
        result["case_partitions"] = page.locator("#casePartitionSelector option").count()
        result["selected_partition"] = page.locator("#casePartitionSelector").input_value() if result["case_partitions"] else None
        if result["case_partitions"] > 1:
            original_partition = result["selected_partition"]
            partition_values = page.locator("#casePartitionSelector option").evaluate_all(
                "options => options.map(option => option.value)"
            )
            alternate_partition = next(value for value in partition_values if value != original_partition)
            page.locator("#casePartitionSelector").select_option(alternate_partition)
            page.wait_for_timeout(1200)
            result["partition_switch"] = {
                "from": original_partition,
                "to": alternate_partition,
                "rendered_case_id": page.locator("#caseTitle").inner_text(),
                "success": page.locator("#caseTitle").inner_text() == alternate_partition,
            }
            page.locator("#casePartitionSelector").select_option(original_partition)
            page.wait_for_timeout(1200)
        result["viewport"] = args.viewport
        layout = page.evaluate("() => ({viewportWidth: innerWidth, documentWidth: document.documentElement.scrollWidth})")
        result["layout"] = {**layout, "horizontal_overflow": layout["documentWidth"] > layout["viewportWidth"]}
        result["breach_summary"] = page.locator("#breachSummary").inner_text() if result["case_visible"] else ""
        result["coverage_gaps"] = (
            page.locator("#gapBanner").inner_text() if page.locator("#gapBanner").is_visible() else ""
        )
        result["claims"] = page.locator("#claimList .item").count()
        result["milestones"] = page.locator("#attackStory .milestone").count()
        result["immediate_decisions"] = page.locator("#immediateDecisions .compact-row").count()
        result["evidence_rows"] = page.locator("[data-evidence]").count()
        if result["case_visible"]:
            for tab, label_text in (("graph", "Causal graph"), ("timeline", "Detailed timeline"),
                                    ("retrieval", "Retrieval trace"), ("actions", "Action plan"),
                                    ("claims", "Evidence")):
                page.get_by_role("tab", name=label_text, exact=True).click()
                page.wait_for_timeout(150)
                result["tabs"][tab] = {
                    "title": page.locator("#stageTitle").inner_text(),
                    "result_count": page.locator("#resultCount").inner_text(),
                }
                if tab == "actions":
                    safe_label = str(label).lower().replace("assessment-", "")
                    page.screenshot(
                        path=str(output / f"{safe_label}-{args.viewport}-action-plan.png"),
                        full_page=True,
                    )
        else:
            result["failure"] = page.locator("#progressText").inner_text() or "assessment_not_ready_before_timeout"
        safe_label = str(label).lower().replace("assessment-", "")
        page.screenshot(path=str(output / f"{safe_label}-{args.viewport}-workspace.png"), full_page=True)
        result["finished_at"] = time.time()
        result["page_errors"] = page_errors
        (output / f"{safe_label}-{args.viewport}-clickthrough.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        browser.close()
    if fixture_server:
        fixture_server.shutdown()
    print(json.dumps(result, indent=2))
    return 0 if (result["case_visible"] and not page_errors
                 and not result["layout"]["horizontal_overflow"]
                 and result.get("partition_switch", {}).get("success", True)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
