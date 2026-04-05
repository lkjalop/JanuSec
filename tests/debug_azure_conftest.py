import sys
import traceback

def pytest_collection_modifyitems(config, items):
    try:
        az = sys.modules.get('azure')
        print('\n[debug_azure_conftest] pytest_collection_modifyitems sys.modules azure ->', az, getattr(az, '__file__', None), getattr(az, '__path__', None))
    except Exception:
        traceback.print_exc()

def pytest_runtest_setup(item):
    try:
        az = sys.modules.get('azure')
        print('\n[debug_azure_conftest] pytest_runtest_setup sys.modules azure ->', az, getattr(az, '__file__', None), getattr(az, '__path__', None))
    except Exception:
        traceback.print_exc()
