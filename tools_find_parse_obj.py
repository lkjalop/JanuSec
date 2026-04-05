import os
matches = []
for root, dirs, files in os.walk('src'):
    for f in files:
        if f.endswith('.py'):
            path = os.path.join(root, f)
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    for i, line in enumerate(fh, start=1):
                        if 'parse_obj(' in line:
                            matches.append((path, i, line.strip()))
            except Exception:
                continue
for root, dirs, files in os.walk('tests'):
    for f in files:
        if f.endswith('.py'):
            path = os.path.join(root, f)
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    for i, line in enumerate(fh, start=1):
                        if 'parse_obj(' in line:
                            matches.append((path, i, line.strip()))
            except Exception:
                continue

for m in matches:
    print(m[0], m[1], m[2])
print('total matches:', len(matches))
