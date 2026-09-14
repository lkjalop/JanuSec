import subprocess
import json
import os


def extract_process_list(memory_file: str, output_dir: str) -> str:
    """Run a minimal extraction using volatility3 or other tool.

    This function is a thin wrapper; in CI we can mock it. It returns
    the path to a JSON file with a process list extracted from the memory image.
    """
    # This is a stub that simulates extraction for testing; replace with
    # a real volatility3 invocation in production.
    out_path = os.path.join(output_dir, os.path.basename(memory_file) + '.processes.json')
    # Simulate a small process list
    data = [{'pid': 1, 'name': 'init'}, {'pid': 1234, 'name': 'suspicious.exe'}]
    with open(out_path, 'w', encoding='utf-8') as fh:
        json.dump(data, fh)
    return out_path
