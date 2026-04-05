import subprocess, sys
files = [
    'tests/test_zeek_adapter.py',
    'tests/test_dread_scorer.py',
    'tests/test_intel_sync.py',
    'tests/test_bgp_network_wiring.py',
    'tests/test_ebpf_smoke.py',
    'tests/test_identity_snapshot.py',
    'tests/test_bgp_metadata_edges.py',
]
for f in files:
    print('\n' + '='*10 + f' RUN {f} ' + '='*10)
    try:
        cp = subprocess.run([sys.executable, '-m', 'pytest', '-q', f], capture_output=True, text=True, timeout=20)
        print('RETURN CODE:', cp.returncode)
        print('--- STDOUT ---')
        print(cp.stdout)
        print('--- STDERR ---')
        print(cp.stderr)
    except subprocess.TimeoutExpired as e:
        print('TIMEOUT after 20s')
        try:
            print(e.stdout)
            print(e.stderr)
        except Exception:
            pass
        # continue to next file
print('\nAll runs attempted')
