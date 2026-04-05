import importlib
import sys
from pathlib import Path

# Ensure repository root is on sys.path so `src` package is importable
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    m = importlib.import_module('src.api.feedback_endpoints')
    print('IMPORT_OK', getattr(m, '__file__', None))
except Exception:
    print('IMPORT_FAILED')
    raise
