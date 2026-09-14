import py_compile, pathlib, sys
errs=0
for p in pathlib.Path('src').rglob('*.py'):
    try:
        py_compile.compile(str(p), doraise=True)
    except py_compile.PyCompileError as e:
        print('COMPILE_ERROR', p, e)
        errs+=1
print('ERRS', errs)
if errs:
    sys.exit(1)
