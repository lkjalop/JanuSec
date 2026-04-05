import re

def extract_mitre_from_factor(factor: str):
    out=[]
    if not isinstance(factor,str):
        return out
    s=factor.strip()
    low=s.lower()
    if low.startswith('mitre:') or low.startswith('mitre_') or low.startswith('mitre-'):
        if ':' in s:
            s = s.split(':',1)[1]
        elif '_' in s:
            s = s.split('_',1)[1]
        elif '-' in s:
            s = s.split('-',1)[1]
        s = s.strip()
    for m in re.findall(r'T\d{4}(?:\.\d{3})?', s, flags=re.IGNORECASE):
        out.append(m.upper())
    for m in re.findall(r'TA\d{4}', s, flags=re.IGNORECASE):
        out.append(m.upper())
    return out

cases = ['mitre_TA0008','T1566.001','mitre:T1059','mitre-T1566.001','net:mitre-T1059-suffix','mitre_T1059']
for c in cases:
    print(c, '->', extract_mitre_from_factor(c))
