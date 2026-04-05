import pandas as pd

df = pd.read_excel('dump/Cyberstash_csv2.xlsx')
print(df['malicious'].unique())
print(df['suspicious'].unique())
