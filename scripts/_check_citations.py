"""Check remaining 'No evidence citation attached' occurrences."""
from pathlib import Path
import re

for label, html_path in [
    ("AZURE", "artifacts/reports/executive_review/azure/2026.04.03-2203Z-contoso.dev-executive-v3.html"),
    ("AWS", "artifacts/reports/executive_review/aws/2026.04.03-2203Z-123456789012-executive-v3.html"),
]:
    html = Path(html_path).read_text(encoding="utf-8")
    positions = [m.start() for m in re.finditer("No evidence citation attached", html)]
    print(f"{label}: {len(positions)} occurrences")
    for pos in positions:
        ctx = html[max(0, pos - 200) : pos + 60]
        # strip tags for readability
        ctx_plain = re.sub(r"<[^>]+>", " ", ctx).strip()
        print(f"  ...{ctx_plain}...")
    print()
