import ast
p='src/api/server.py'
try:
    s=open(p,'r',encoding='utf-8').read()
    ast.parse(s)
    print('ok')
except SyntaxError as e:
    print('SyntaxError:', e.msg, 'line', e.lineno)
    # print context
    lines=s.splitlines()
    for i in range(max(1,e.lineno-5), e.lineno+5):
        print(f"{i:4}: {lines[i-1]}")
except Exception as e:
    print('other error', e)
