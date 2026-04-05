import sys
sys.path.insert(0, '.')
from src.core import arc_redis_queue as q
print('module', q)
print('has enqueue_job:', hasattr(q, 'enqueue_job'))
