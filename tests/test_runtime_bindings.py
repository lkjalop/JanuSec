from src.api.server import FILE_HASH_FACTORS, app
from src.api.runtime_state import get_file_hash_factors, get_server_runtime_state


def test_file_hash_factors_identity():
    runtime = get_server_runtime_state(app)
    canon = get_file_hash_factors(runtime)
    # exported symbol should reference the canonical mapping
    assert FILE_HASH_FACTORS is canon
