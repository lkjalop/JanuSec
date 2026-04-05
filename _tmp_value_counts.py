import pandas as pd

df = pd.read_excel('dump/Cyberstash_csv2.xlsx')
print(df['suspicious'].value_counts())
print(df['unknown'].value_counts())
