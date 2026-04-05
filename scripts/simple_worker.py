import redis
import json
import time

RC = redis.from_url('redis://127.0.0.1:6379/0')
GLOBAL_Q = 'llm:tasks'

print('simple_worker connecting to redis')

try:
    while True:
        res = RC.blpop(GLOBAL_Q, timeout=5)
        if not res:
            continue
        _, payload = res
        if isinstance(payload, bytes):
            payload = payload.decode()
        try:
            task = json.loads(payload)
        except Exception:
            print('bad payload', payload)
            continue
        aid = task.get('assessment_id', 'unknown')
        tid = task.get('task_id')
        print('processing', aid, tid)
        # simulate processing
        time.sleep(1)
        result = {'text': 'smoke processed', 'task_id': tid}
        ch = f'assessment:events:{aid}'
        msg = {
            'type': 'partial_result',
            'assessment_id': aid,
            'task_id': tid,
            'result': result,
            'last_updated_ts': time.time(),
        }
        RC.publish(ch, json.dumps(msg))
        print('published to', ch)
except KeyboardInterrupt:
    print('worker exiting')
