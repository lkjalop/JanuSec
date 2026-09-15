"""Calibration Export Tools

Provides helpers to export calibration datasets to CSV and render a basic HTML summary.
"""
from __future__ import annotations

import html
import os
from typing import Optional

from .dataset_builder import export_calibration_dataset


def export_csv_and_html(csv_path: str, html_path: Optional[str] = None, limit: int = 2000) -> dict:
    res = export_calibration_dataset(out_csv=csv_path, limit=limit)
    if html_path:
        # very basic HTML summary
        count = res.get("count", 0)
        body = f"<html><head><title>Calibration Export</title></head><body><h1>Calibration Export</h1><p>Rows: {count}</p><p>CSV: {html.escape(csv_path)}</p></body></html>"
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(body)
        res["html"] = html_path
    return res


if __name__ == "__main__":  # simple CLI
    out_csv = os.getenv("CAL_EXPORT_CSV", "calibration_export.csv")
    out_html = os.getenv("CAL_EXPORT_HTML")
    limit = int(os.getenv("CAL_EXPORT_LIMIT", "2000"))
    info = export_csv_and_html(out_csv, out_html, limit=limit)
    print(info)

__all__ = ["export_csv_and_html"]
