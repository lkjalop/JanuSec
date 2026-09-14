import importlib,sys,traceback
import os
p='d:/AI/Threat_thy_sniffer/src/api/deep_analyze_endpoints.py'
root = os.path.abspath(os.path.join(os.path.dirname(p),'..','..'))
sys.path.insert(0, root)
print('READ_BYTES',len(open(p,'rb').read()))
text=open(p,'r',encoding='utf-8').read()
print('FUTURE_COUNT', text.count('from __future__ import annotations'))
for i,line in enumerate(text.splitlines(),start=1):
    if 'from __future__ import annotations' in line:
        print('FUTURE_LINE',i)
try:
    if 'src.api' in sys.modules:
        del sys.modules['src.api.deep_analyze_endpoints']
    m=importlib.import_module('src.api.deep_analyze_endpoints')
    print('IMPORT_OK', hasattr(m,'router'))
except Exception:
    traceback.print_exc()
