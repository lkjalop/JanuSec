import csv,os
csvp='data/correlation_rules_inventory.csv'
if not os.path.exists(csvp):
    print('csv not found')
else:
    with open(csvp,'r',encoding='utf-8') as f:
        r=csv.DictReader(f)
        rows=[row for row in r if row.get('placeholder','').lower()=='true']
    print('placeholder count=',len(rows))
    for row in rows[:20]:
        print(row['path'], row['size'], row['lines'])
