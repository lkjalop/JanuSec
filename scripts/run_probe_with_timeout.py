import os
os.environ['OLLAMA_TIMEOUT_SECONDS'] = os.environ.get('OLLAMA_TIMEOUT_SECONDS', '300')
import runpy
runpy.run_path('scripts/ollama_probe.py', run_name='__main__')
