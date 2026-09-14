import sys, time, importlib
if len(sys.argv) < 2:
    print('usage: import_test.py module.name')
    sys.exit(2)
modname = sys.argv[1]
start = time.time()
try:
    importlib.import_module(modname)
    print('imported', modname, 'elapsed', time.time()-start)
except Exception as e:
    print('import failed for', modname)
    raise
