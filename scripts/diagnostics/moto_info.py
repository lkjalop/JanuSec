import moto
import pkgutil
import inspect
print('moto_file=', getattr(moto, '__file__', None))
print('has_mock_s3=', hasattr(moto, 'mock_s3'))
print('has_mock_sqs=', hasattr(moto, 'mock_sqs'))
print('submods=', [p.name for p in pkgutil.iter_modules(moto.__path__)])
try:
    import importlib
    spec = importlib.util.find_spec('moto.s3')
    print('moto.s3 spec=', spec)
except Exception as e:
    print('moto.s3 import error', e)
