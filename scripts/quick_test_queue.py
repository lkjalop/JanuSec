import os
import shutil
import sys

# Ensure filesystem mode (force no Redis)
os.environ.pop('RESIGN_JOBS_REDIS_URL', None)
os.environ.pop('RATE_LIMIT_REDIS_URL', None)

# Clean queue dir
qdir = os.path.join('data', 'resign_jobs')
if os.path.exists(qdir):
    shutil.rmtree(qdir)

sys.path.insert(0, '.')
from src.core import arc_redis_queue_impl as q

print('module', q)
print('functions:', [a for a in dir(q) if a in ('enqueue_job', 'pop_job', 'ack_job', 'get_redis_client')])

job = {'type': 'resign_exports', 'path_prefix': '/tmp', 'key_id': 'k1'}
jid = q.enqueue_job(job.copy())
print('enqueued', jid)
print('queue dir listing after enqueue:')
for f in sorted(os.listdir('data/resign_jobs')):
    print(' -', f)

res = q.pop_job(timeout=1)
print('pop returned:', res is not None)
if res:
    job_obj, raw = res
    print('job:', job_obj)
    q.ack_job(raw)
    print('acked')

print('queue dir listing after ack:')
if os.path.exists('data/resign_jobs'):
    for f in sorted(os.listdir('data/resign_jobs')):
        print(' -', f)
else:
    print('(no dir)')
