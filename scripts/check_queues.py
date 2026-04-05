import redis

rc = redis.from_url('redis://127.0.0.1:6379/0')
print('llm:tasks length =', rc.llen('llm:tasks'))
print("llm:queue:smoke-assess-1 length =", rc.llen('llm:queue:smoke-assess-1'))
print('llm:priority zcard =', rc.zcard('llm:priority'))
print('sample from global queue:', rc.lrange('llm:tasks', 0, 5))
print('sample per-assessment:', rc.lrange('llm:queue:smoke-assess-1', 0, 5))
