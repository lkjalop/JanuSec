import os, subprocess, sys
os.environ['LLM_MOCK']='1'
print('LLM_MOCK=', os.environ['LLM_MOCK'])
code = subprocess.call([sys.executable, '-m', 'pytest', '-q', 'tests/test_llm_flow_smoke.py'])
print('exit', code)
sys.exit(code)
