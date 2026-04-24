import lark, sys, importlib
print('lark.__file__ =', getattr(lark, '__file__', None))
print('HAS UnexpectedInput attr in lark module:', 'UnexpectedInput' in dir(lark))
try:
    from lark import UnexpectedInput
    print('Imported UnexpectedInput from lark: OK')
except Exception as e:
    print('Import UnexpectedInput from lark: FAILED ->', repr(e))
spec = importlib.util.find_spec('lark')
print('spec.origin =', getattr(spec, 'origin', None))
print('sys.path[0:6] =', sys.path[0:6])
