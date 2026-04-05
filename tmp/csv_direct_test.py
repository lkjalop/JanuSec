import os, asyncio
os.environ['MAX_CSV_ROWS']='100'
from src.api.csv_handler import CSVProcessor
p=CSVProcessor()
# build csv with header + 1000 rows
lines=['a,b,c']+[f"{i},{i+1},{i+2}" for i in range(1000)]
data=('\n'.join(lines)).encode('utf-8')
res=asyncio.get_event_loop().run_until_complete(p.process_csv(data,'big.csv'))
import json
print(json.dumps(res, indent=2)[:1000])
