import os, subprocess, sys
os.environ['TIER2_CLEAN_INTERVAL'] = '0'
files = ['tests/test_llm_queue_endpoints.py', 'tests/test_tier2_llm_client.py', 'tests/test_tier2_queue.py']
print('Running', files)
code = subprocess.call([sys.executable, '-m', 'pytest', '-q', '-s'] + files)
print('exit', code)
sys.exit(code)
