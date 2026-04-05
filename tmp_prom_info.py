import prometheus_client
from prometheus_client import CollectorRegistry
import inspect
print('module:', CollectorRegistry.__module__)
print('prometheus_client file:', getattr(prometheus_client, '__file__', 'n/a'))
print('has collect attr on class?', hasattr(CollectorRegistry, 'collect'))
