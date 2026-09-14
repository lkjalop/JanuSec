import time
from src.api.runtime_state import get_server_runtime_state, get_file_batch_analysis
from src.api.app import app as _app
from src.core.detectors.dns_exfil import dns_exfil_factors
from src.core.detectors.file_hash_rarity import file_hash_rarity_factors, update_runtime_hash_history


def test_dns_exfil_detector_seeded():
    runtime = get_server_runtime_state(_app)
    runtime.nx_rate_tracker.clear()
    # seed a producer with many NXDOMAIN True samples
    runtime.nx_rate_tracker['zeek:exfil.example.com'].extend([True] * 40 + [False] * 10)
    # add some dns samples for entropy
    runtime.dns_query_samples = {'zeek:exfil.example.com': [f"{i}a7g{i}.exfil.example.com" for i in range(20)]}
    factors = dns_exfil_factors(runtime, min_samples=5, nx_threshold=0.3)
    assert isinstance(factors, list)
    assert any(f.get('factor') == 'dns_exfil' for f in factors), f"expected dns_exfil factors, got {factors}"


def test_file_hash_rarity_and_update():
    runtime = get_server_runtime_state(_app)
    # clear history
    runtime.file_hash_factors = {}
    # seed one observed file batch
    files = [{'sha256': 'hrare1'}, {'sha256': 'hcommon'}]
    # simulate history so hcommon appears often
    runtime.file_hash_factors['hcommon'] = [1] * 50
    # update hashed history with new observation
    update_runtime_hash_history(runtime, files)
    # now compute rarity
    res = file_hash_rarity_factors(runtime, files, rarity_threshold=0.2)
    assert any(r.get('sha256') == 'hrare1' for r in res), f"expected rare hash hrare1 in {res}"