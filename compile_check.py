import py_compile, traceback
try:
    py_compile.compile('tests/conftest.py', doraise=True)
    print('OK')
except Exception as e:
    traceback.print_exc()
