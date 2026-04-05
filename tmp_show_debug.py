print('--- debug file contents ---')
try:
    with open('incidents_debug.log','r',encoding='utf-8') as f:
        print(f.read())
except Exception as e:
    print('failed to read debug file', e)
