"""Spot-check the fixed items in both regenerated HTML reports."""
from pathlib import Path
from html.parser import HTMLParser


class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text = []
        self.current_skip = []
        self.skip_tags = {"script", "style"}

    def handle_starttag(self, tag, attrs):
        if tag in self.skip_tags:
            self.current_skip.append(tag)

    def handle_endtag(self, tag):
        if self.current_skip and self.current_skip[-1] == tag:
            self.current_skip.pop()

    def handle_data(self, data):
        if not self.current_skip:
            s = data.strip()
            if s:
                self.text.append(s)


CHECKS = {
    "AZURE": {
        "path": "artifacts/reports/executive_review/azure/2026.04.03-2203Z-contoso.dev-executive-v3.html",
        "must_contain": [
            "Broader impact still possible",
            "Supported",           # Broader impact is now Supported
            "Sensitive resource access was observed",
            "Confirmed",
            "E5",                  # KV evidence ref appears
            "NSG Flow",            # source label
        ],
        "must_not_contain": [
            "nsg-prod-eastus-001\"/",  # raw full ARM — partial name in humanised label is OK
        ],
    },
    "AWS": {
        "path": "artifacts/reports/executive_review/aws/2026.04.03-2203Z-123456789012-executive-v3.html",
        "must_contain": [
            "Broader impact still possible",
            "Supported",
            "Sensitive resource access was observed",
            "prod-data-warehouse-ap2",    # GuardDuty S3 bucket name in resource col
            "DevOpsRole",                 # GuardDuty AccessKeyDetails user
            "E6",                         # VPC flow evidence ref
            "network",                    # VPC flow domain now 'network'
        ],
        # The 1 remaining "No evidence citation attached" is the legitimate
        # "Business loss" claim which has no refs by design — that is expected.
        "trend_check": True,
    },
}


def check(label, cfg):
    html = Path(cfg["path"]).read_text(encoding="utf-8")
    p = TextExtractor()
    p.feed(html)
    body = " ".join(p.text)

    print(f"\n=== {label} ===")
    all_ok = True
    for check_str in cfg.get("must_contain", []):
        found = check_str.lower() in body.lower()
        status = "OK  " if found else "FAIL"
        if not found:
            all_ok = False
        print(f"  [{status}] must contain:     {check_str!r}")

    for check_str in cfg.get("must_not_contain", []):
        found = check_str.lower() in body.lower()
        status = "FAIL" if found else "OK  "
        if found:
            all_ok = False
        print(f"  [{status}] must NOT contain: {check_str!r}")

    if cfg.get("trend_check"):
        # look for trend items > 1
        import re
        counts = re.findall(r"(\d+) reviewed items", body)
        max_count = max(int(c) for c in counts) if counts else 0
        ok = max_count > 1
        if not ok:
            all_ok = False
        print(f"  [{'OK  ' if ok else 'FAIL'}] trend windows show >1 reviewed item (max={max_count})")

    print(f"  => {'ALL OK' if all_ok else 'SOME CHECKS FAILED'}")


for label, cfg in CHECKS.items():
    check(label, cfg)
