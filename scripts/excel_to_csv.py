import pandas as pd
import sys
from pathlib import Path

infile = Path('dump/Cyberstash_csv2.xlsx')
if not infile.exists():
    print('Input file not found:', infile)
    sys.exit(2)

out_dir = Path('dump/csv_from_excel')
out_dir.mkdir(parents=True, exist_ok=True)

try:
    xls = pd.ExcelFile(infile)
except Exception as e:
    print('Failed to open Excel file:', e)
    sys.exit(3)

print('Sheets:', xls.sheet_names)
for sheet in xls.sheet_names:
    try:
        df = xls.parse(sheet)
    except Exception as e:
        print(f'Failed to parse sheet {sheet}:', e)
        continue
    out_csv = out_dir / f"{infile.stem}_{sheet}.csv"
    try:
        df.to_csv(out_csv, index=False)
        print('Wrote', out_csv)
    except Exception as e:
        print('Failed writing CSV:', e)
        continue
    # write a small sample
    sample_csv = out_dir / f"{infile.stem}_{sheet}_sample.csv"
    try:
        df.head(500).to_csv(sample_csv, index=False)
        print('Wrote sample', sample_csv)
    except Exception as e:
        print('Failed writing sample CSV:', e)

print('Done')
