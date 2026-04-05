import pandas as pd
from pathlib import Path

for name in ['dump/Cyberstash_csv2.xlsx', 'dump/cybstash csv1.xlsx']:
    path = Path(name)
    df = pd.read_excel(path)
    print(f"{name}: rows={len(df)} cols={len(df.columns)}")
    print("columns:", list(df.columns)[:15])
    print(df.head(2))
    print('-'*60)
