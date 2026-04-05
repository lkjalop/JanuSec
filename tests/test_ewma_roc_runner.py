import subprocess
import os

def test_run_ewma_roc():
    # run the ewma_roc script and ensure CSV output exists
    path = os.path.join('scripts', 'ewma_roc.py')
    res = subprocess.run(['python', path], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    assert os.path.exists('ewma_roc_summary.csv')
