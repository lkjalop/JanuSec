import os, subprocess, sys
os.environ['CI']='1'
print('CI=', os.environ['CI'])
print('LLM_MOCK before:', os.environ.get('LLM_MOCK'))
code = subprocess.call([sys.executable, '-m', 'pytest', '-q', '-k', 'llm'])
print('exit', code)
