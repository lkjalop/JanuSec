import sys
import traceback
import py_compile

def compile_file(path):
    try:
        py_compile.compile(path, doraise=True)
        print('OK')
    except Exception:
        traceback.print_exc()
        sys.exit(2)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python py_compile_file.py <path>')
        sys.exit(1)
    compile_file(sys.argv[1])
