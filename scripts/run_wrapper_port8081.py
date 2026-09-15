import os
os.environ.setdefault('PORT', '8081')
import runpy
runpy.run_path('scripts/run_uvicorn_wrapper.py', run_name='__main__')
