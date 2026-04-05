import inspect
from src.api import server as s

print('decisions_repo in globals?', 'decisions_repo' in s.__dict__)
print('decisions_repo object repr:', repr(getattr(s,'decisions_repo', None)))
dr = getattr(s,'decisions_repo', None)
if dr:
    print('methods:', [m for m in dir(dr) if m.startswith('list') or m.startswith('persist')])
print('factor_promotion_status first lines:')
print('\n'.join(inspect.getsource(s.factor_promotion_status).splitlines()[:40]))