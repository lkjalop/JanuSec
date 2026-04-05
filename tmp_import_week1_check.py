import importlib
import traceback

try:
    m = importlib.import_module('src.core.correlation.rules.week1.office_macro_chain')
    print('module imported:', m.__name__)
    from src.core.correlation.rules.registry import CORRELATION_RULES
    print('registered rules sample:', list(CORRELATION_RULES._rules.keys())[:10])
except Exception:
    traceback.print_exc()
    print('import failed')
