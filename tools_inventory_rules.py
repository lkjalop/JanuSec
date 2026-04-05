import os, csv
root='src/core/correlation/rules'
rows=[]
for dirpath,dirnames,filenames in os.walk(root):
    for fn in filenames:
        if fn.endswith('.py'):
            p=os.path.join(dirpath,fn)
            try:
                st=os.stat(p)
                with open(p,'r',encoding='utf-8') as fh:
                    txt=fh.read()
                lines=txt.count('\n')+1
                placeholder = 'Placeholder' in txt or len(txt.strip())<200
                rows.append({'path':p.replace('\\','/'),'size':st.st_size,'lines':lines,'placeholder':placeholder})
            except Exception:
                continue

out='data/correlation_rules_inventory.csv'
os.makedirs(os.path.dirname(out),exist_ok=True)
with open(out,'w',newline='',encoding='utf-8') as csvf:
    w=csv.DictWriter(csvf,fieldnames=['path','size','lines','placeholder'])
    w.writeheader()
    for r in sorted(rows,key=lambda x:x['path']):
        w.writerow(r)
print('wrote',out,'rows=',len(rows))
