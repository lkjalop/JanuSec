import sys
import site
import pprint
import os

def main():
    print('sys.executable=', sys.executable)
    print('sys.prefix=', sys.prefix)
    print('sys.path[0]=', sys.path[0] if sys.path else None)
    print('ENABLE_USER_SITE=', getattr(site, 'ENABLE_USER_SITE', None))
    try:
        print('getusersitepackages=', site.getusersitepackages())
    except Exception as e:
        print('getusersitepackages failed:', e)
    print('\nfirst 30 sys.path entries:')
    for p in sys.path[:30]:
        print(p)
    print('\nsite.getsitepackages():')
    try:
        pprint.pprint(site.getsitepackages())
    except Exception as e:
        print('getsitepackages failed:', e)

if __name__ == '__main__':
    main()
