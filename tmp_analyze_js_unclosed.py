from pathlib import Path
p=Path('frontend/static/js/csv_analyzer.js')
s=p.read_text(encoding='utf-8',errors='replace')
# find all occurrences of '/*' and '*/'
starts=[i for i in range(len(s)) if s.startswith('/*', i)]
ends=[i for i in range(len(s)) if s.startswith('*/', i)]
print('len', len(s), 'starts', len(starts), 'ends', len(ends))
# show last 5 starts and ends with context
for x in starts[-5:]:
    print('start at', x, 'line', s.count('\n',0,x)+1)
for x in ends[-5:]:
    print('end at', x, 'line', s.count('\n',0,x)+1)
# find last occurrence of single-line comment without newline? unlikely
# check for unmatched parentheses/brackets counts
for ch in ['{','}','(',')','[',']']:
    print(ch, s.count(ch))
# check if file ends with closing paren or semicolon
print('endswith );', s.strip().endswith(');'))
print('endswith }', s.strip().endswith('}'))
print('last 200 chars:\n', s[-200:])
