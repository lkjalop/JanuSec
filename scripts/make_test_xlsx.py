#!/usr/bin/env python3
"""Create a minimal XLSX file for Playwright tests.

Usage:
  python scripts/make_test_xlsx.py <output_path>
"""
import sys
from pathlib import Path

def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('tests/playwright/fixtures/test_upload.xlsx')
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        from openpyxl import Workbook
    except Exception as e:
        print('ERROR: openpyxl is required to generate XLSX fixture:', e)
        sys.exit(2)

    wb = Workbook()
    ws = wb.active
    ws.title = 'Sheet1'
    ws.append(['col1', 'col2'])
    ws.append(['A', 1])
    ws.append(['B', 2])
    wb.save(out)
    print(str(out))

if __name__ == '__main__':
    main()
