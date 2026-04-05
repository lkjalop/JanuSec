import pandas as pd
from pathlib import Path

path = Path('dump/Cyberstash_csv2.xlsx')
df = pd.read_excel(path)
print(df.columns.tolist())
