import moto
import pkgutil
import sys
print('moto_file=', getattr(moto, '__file__', None))
print('sys.path[0]=', sys.path[0] if sys.path else None)
print('submods=', [p.name for p in pkgutil.iter_modules(moto.__path__)])
