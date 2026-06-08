"""Download D3.js v7 and vendor it locally for air-gapped / self-hosted deployments.

Usage:
    python scripts/vendor_d3.py

After running, update attack_graph.html to use the local path:
    <script src="/static/js/d3.v7.min.js"></script>
"""
import sys
import urllib.request
from pathlib import Path

D3_URL = "https://d3js.org/d3.v7.min.js"
DEST = Path(__file__).parent.parent / "frontend" / "static" / "js" / "d3.v7.min.js"


def main() -> None:
    if DEST.exists():
        print(f"Already exists: {DEST}")
        return

    print(f"Downloading D3.js v7 from {D3_URL} ...")
    try:
        with urllib.request.urlopen(D3_URL, timeout=30) as resp:  # noqa: S310
            data = resp.read()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    DEST.parent.mkdir(parents=True, exist_ok=True)
    DEST.write_bytes(data)
    print(f"Saved {len(data):,} bytes to {DEST}")
    print()
    print("To use locally, replace the CDN script tag in attack_graph.html:")
    print('  <script src="/static/js/d3.v7.min.js"></script>')


if __name__ == "__main__":
    main()
