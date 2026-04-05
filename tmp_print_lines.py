from pathlib import Path
p=Path('src/api/server.py')
lines=p.read_text().splitlines()
for i in range(1648,1708):
    print(i+1, repr(lines[i]))
