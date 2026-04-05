import os
import subprocess
import sys

# Ensure we do NOT set LLM_MOCK so tests hit Ollama
os.environ.pop('LLM_MOCK', None)
print('LLM_MOCK=', os.environ.get('LLM_MOCK'))
files = [
    'tests/test_ollama_llm.py',
    'tests/test_llm_flow_smoke.py',
    'tests/test_llm_row_handling_regression.py',
    'tests/test_llm_queue_endpoints.py',
    'tests/test_tier2_llm_client.py',
    'tests/test_tier2_queue.py'
]
print('Running tests:', files)
code = subprocess.call([sys.executable, '-m', 'pytest', '-q'] + files)
print('exit', code)
sys.exit(code)
