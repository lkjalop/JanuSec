import json
p='openapi.json'
try:
    d=json.load(open(p))
    for k in sorted(d.get('paths',{}).keys()):
        if 'config' in k or 'assess' in k:
            print(k)
except Exception as e:
    print('err',e)
