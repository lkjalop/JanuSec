import subprocess
from pathlib import Path
root=Path('d:/AI/Threat_thy_sniffer')
orig=root/'frontend'/'static'/'js'/'csv_analyzer.js'
text=orig.read_text(encoding='utf-8',errors='replace')
suffixes=['\n}', '\n)', '\n})', '\n});', '\n})();', '\n});\n)']
check = root/'tmp_check_js_syntax.js'
for s in suffixes:
    tmp=root/('tmp_test'+str(len(s))+'.js')
    tmp.write_text(text+s, encoding='utf-8')
    proc=subprocess.run(['node', str(check), str(tmp)], capture_output=True, text=True)
    ok = proc.returncode==0
    print(s, 'OK' if ok else 'FAIL', 'rc', proc.returncode)
    if not ok:
        err=proc.stderr.strip()
        print('  stderr:', err.splitlines()[-3:])
    tmp.unlink()
