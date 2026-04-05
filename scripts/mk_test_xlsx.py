#!/usr/bin/env python3
"""Create a tiny XLSX fixture used by Playwright tests

Writes to: tests/playwright/fixtures/test_upload.xlsx
"""
from pathlib import Path
from openpyxl import Workbook

def main():
    out = Path(__file__).parent.parent / 'tests' / 'playwright' / 'fixtures'
    out.mkdir(parents=True, exist_ok=True)
    fp = out / 'test_upload.xlsx'
    wb = Workbook()
    ws = wb.active
    ws.title = 'Sheet1'
    ws.append(['col1', 'col2'])
    ws.append(['A', 1])
    ws.append(['B', 2])
    wb.save(fp)
    print(f'Wrote fixture: {fp}')

if __name__ == '__main__':
    main()
