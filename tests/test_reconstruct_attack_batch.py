import json, subprocess, sys, os

SCRIPT = 'scripts/reconstruct_attack_batch.py'


def test_reconstruct_attack_batch_offline():
    assert os.path.exists(SCRIPT), 'Script missing'
    # Run without live posting
    proc = subprocess.run([sys.executable, SCRIPT, '--fixture', 'tests/fixtures/e2e_multi_domain_attack.json'], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout.strip()
    data = json.loads(out)
    assert data['event_count'] >= 5
    assert 'domain_counts' in data and data['domain_counts']
    assert len(data.get('expected_factors', [])) >= 5
    assert data.get('attack_id') == 'multi-domain-1'
