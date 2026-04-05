import subprocess
import sys
import json
from pathlib import Path


DATA_DIR = Path('tests') / 'data' / 'auto_audit'


def run_runner():
    # run the runner script in a subprocess with clean PYTHONPATH
    env = dict(**{})
    cmd = [sys.executable, 'scripts/run_auto_audit_vectors.py']
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if proc.returncode != 0:
        raise RuntimeError(f"Runner failed: {proc.returncode}\n{proc.stderr}")
    return proc.stdout


EXPECTED = {
    'office_macro_chain_docm.json': ['office_macro_spawn_powershell', 'corr_office_macro_ps'],
    'amsi_bypass_powershell_encoded.json': ['corr_amsi_bypass'],
    'ca_lsass_access_seq.json': ['ca_lsass_access_seq'],
    'pe_token_theft_combo.json': ['pe_token_theft_combo'],
    'filesystem_encryption_trigger.json': ['filesystem_encryption_trigger'],
    'registry_run_key.json': ['corr_registry_run_keys'],
    'new_service_nonstandard.json': ['corr_new_service_nonstandard_path', 'persistence_new_service_nonstandard_enriched'],
    'imp_stop_security_services.json': ['imp_stop_security_services'],
    'cred_dump_lsass_trace.json': ['cred_dump_lsass_trace'],
    'exec_mshta_remote_event.json': ['exec_mshta_remote'],
    'pers_scheduled_task_lolbin_args_event.json': ['pers_scheduled_task_lolbin_args'],
}


def test_runner_outputs_expected_rules():
    out = run_runner()
    # parse lines like: "file.json -> fired: ['rule1','rule2']"
    for line in out.splitlines():
        if '-> fired:' not in line:
            continue
        try:
            left, right = line.split('-> fired:')
            fname = left.strip()
            fired = json.loads(right.strip().replace("'", '"'))
        except Exception:
            continue
        base = Path(fname).name
        if base in EXPECTED:
            for ex in EXPECTED[base]:
                assert ex in fired, f"Expected {ex} in fired list for {base}: {fired}"
