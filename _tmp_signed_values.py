import pandas as pd

df = pd.read_excel('dump/Cyberstash_csv2.xlsx')
print(df['signed'].unique()[:10])
