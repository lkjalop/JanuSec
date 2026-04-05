import prometheus_client, inspect
from prometheus_client import CollectorRegistry
print('prometheus_client', getattr(prometheus_client, '__version__', 'unknown'))
print('CollectorRegistry has collect?', hasattr(CollectorRegistry, 'collect'))
print('collect attr type:', type(getattr(CollectorRegistry, 'collect', None)))
print('dir sample:', [n for n in dir(CollectorRegistry) if 'collect' in n or 'get' in n][:40])
