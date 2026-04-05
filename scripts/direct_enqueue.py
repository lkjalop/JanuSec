import redis
import json
import uuid

RC = redis.from_url('redis://127.0.0.1:6379/0')
AID = 'smoke-assess-1'
TASK = {
    'task_id': str(uuid.uuid4()),
    'assessment_id': AID,
    'payload': {'text': 'ransom encryption detected; suspicious exe'},
    'persona': 'soc',
}
PAYLOAD = json.dumps(TASK)
# push to per-assessment
RC.rpush(f'llm:queue:{AID}', PAYLOAD)
# push to global
RC.rpush('llm:tasks', PAYLOAD)
# add to priority zset with score 1.0
RC.zadd('llm:priority', {PAYLOAD: 1.0})
print('enqueued', TASK['task_id'])
