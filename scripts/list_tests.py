import os, fnmatch

pattern = 'test_*.py'
paths = ['tests']
matches = []
for p in paths:
    for root, dirs, files in os.walk(p):
        for f in files:
            if fnmatch.fnmatch(f, pattern):
                matches.append(os.path.join(root,f))
print('Found', len(matches), 'candidate test files (first 20):')
for m in matches[:20]:
    print(m)
