from __future__ import annotations

import argparse
import sys
from pathlib import Path
from ml.dataset_builder import collect_calibration_rows, to_csv, to_html


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Export calibration dataset to CSV/HTML")
    p.add_argument("--limit", type=int, default=1000, help="Max rows to export")
    p.add_argument("--out-csv", type=Path, default=Path("calibration_export.csv"))
    p.add_argument("--out-html", type=Path, default=Path("calibration_export.html"))
    args = p.parse_args(argv)

    rows = collect_calibration_rows(limit=args.limit)
    csv_text = to_csv(rows)
    html_text = to_html(rows)
    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    args.out_html.parent.mkdir(parents=True, exist_ok=True)
    args.out_csv.write_text(csv_text, encoding="utf-8")
    args.out_html.write_text(html_text, encoding="utf-8")
    print(f"Wrote {len(rows)} rows to {args.out_csv} and {args.out_html}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
