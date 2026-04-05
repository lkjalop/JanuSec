import os
import pytest
import vcr
from src.adapters.run_qualys_ingest import main as ingest_main


@pytest.mark.skipif(not (os.environ.get('QUALYS_CLIENT_ID') and os.environ.get('QUALYS_CLIENT_SECRET')),
                    reason='Qualys credentials not provided')
def test_record_live_cassette(tmp_path):
    cassette_dir = os.path.join(os.path.dirname(__file__), 'cassettes')
    os.makedirs(cassette_dir, exist_ok=True)
    cassette_name = 'live_qualys_recording.yml'
    myvcr = vcr.VCR(record_mode='all', cassette_library_dir=cassette_dir)
    # Run the ingest runner under a cassette context
    with myvcr.use_cassette(cassette_name):
        # The ingest runner expects CLI args; call it as a subprocess would.
        # Using the module directly may be fine, but to capture all requests
        # reliably we prefer the subprocess invocation in recording script.
        # For simplicity, call the script entry point with env vars available.
        ingest_main()
