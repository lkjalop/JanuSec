from pathlib import Path
p=Path('src/api/server.py')
s=p.read_text()
for i,l in enumerate(s.splitlines(), start=1):
    if l.strip().startswith('finally:'):
        print(i, l)
print('---')
stack=0
for i,l in enumerate(s.splitlines(), start=1):
    s=l.strip()
    if s.startswith('try:'):
        stack+=1
    if s.startswith('except') or s.startswith('finally:'):
        if stack>0:
            stack-=1
        else:
            print('unmatched except/finally at', i, s)
            break
else:
    if stack>0:
        print('unmatched try blocks remain:', stack)
    else:
        print('balanced up to EOF')
