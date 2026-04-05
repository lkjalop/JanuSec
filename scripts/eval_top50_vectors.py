import sys, json, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from src.core.correlation.rules.registry import CORRELATION_RULES

vecs = ['vec_suspicious_rundll32','vec_onedrive_unauth','vec_staged_scripts_temp','vec_certutil','vec_wevtutil','vec_autorun_registry','vec_schtasks','vec_powershell_enc','vec_at_command','vec_netstat_highport']
out = []
for v in vecs:
    p = pathlib.Path('tests')/'data'/'top50'/(v + '.json')
    try:
        data = json.loads(p.read_text(encoding='utf-8'))
    except Exception as e:
        out.append({'vector': v, 'error': str(e)})
        continue
    fired = [r.name for r in CORRELATION_RULES.evaluate(data)]
    out.append({'vector': v, 'fired': fired})

o = pathlib.Path('data')/'top50_eval_results.json'
o.parent.mkdir(parents=True, exist_ok=True)
o.write_text(json.dumps(out, indent=2), encoding='utf-8')
print('Wrote', o)
