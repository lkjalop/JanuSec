import importlib
import sys
m = importlib.import_module('tests.test_auto_accept_and_repo')
print('module imported, has client?', hasattr(m, 'client'))
# Call the test function
try:
    m.test_auto_accept_and_repo(tmp_path=None)
except TypeError:
    # function expects tmp_path fixture; ignore and call without
    try:
        m.test_auto_accept_and_repo()
    except Exception as e:
        print('exception from test call:', e)
except Exception as e:
    print('exception from test call:', e)
print('done')
