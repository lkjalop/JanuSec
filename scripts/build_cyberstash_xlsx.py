"""Build an Excel workbook `Cyberstash_csv2.xlsx` in `dump/` composing Network, Endpoint, Email, EDR, C2 sheets."""
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
DUMP = ROOT / 'dump'


def build():
    out = DUMP / 'Cyberstash_csv2.xlsx'
    sheets = {}
    for name in ['network','endpoint','email','edr','c2']:
        p = DUMP / f"{name}.csv"
        if p.exists():
            sheets[name] = pd.read_csv(p)
    with pd.ExcelWriter(out) as w:
        for k,v in sheets.items():
            v.to_excel(w, sheet_name=k.capitalize(), index=False)
    print('Wrote', out)


if __name__ == '__main__':
    build()
