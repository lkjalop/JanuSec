import pandas as pd

df = pd.read_excel('dump/Cyberstash_csv2.xlsx')
print(df[['name','path','signed','threatScore']].head())
