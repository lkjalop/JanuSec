import subprocess,sys,os
p='frontend/static/js/csv_analyzer.js'
with open(p,'r',encoding='utf-8',errors='replace') as f:
    lines=f.readlines()
lo=1; hi=len(lines)
last_ok=0
while lo<=hi:
    mid=(lo+hi)//2
    tmp='tmp_prefix.js'
    with open(tmp,'w',encoding='utf-8') as tf:
        tf.writelines(lines[:mid])
    # run node compile
    proc=subprocess.run(['node','tmp_check_js_syntax.js', tmp], capture_output=True, text=True)
    ok = proc.returncode==0
    if ok:
        last_ok=mid
        lo=mid+1
    else:
        hi=mid-1
print('last_ok', last_ok, 'of', len(lines))
if last_ok<len(lines):
    print('\n--- context around failure ---')
    s=max(0,last_ok-5)
    for i in range(s, min(len(lines), last_ok+5)):
        print(i+1, lines[i].rstrip('\n'))
    
# cleanup
try:
    os.remove('tmp_prefix.js')
except:
    pass
