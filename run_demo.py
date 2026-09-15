"""Run a small demo server for SultryTAI (FastAPI)

Usage:
    python run_demo.py
"""
import uvicorn

if __name__ == '__main__':
    uvicorn.run('sultrytai.api:app', host='127.0.0.1', port=9000, reload=False)
