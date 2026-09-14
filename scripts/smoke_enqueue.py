from src.core.redis_llm_queue import enqueue_task

if __name__ == '__main__':
    tid = enqueue_task('smoke-assess-1', {'payload': {'text': 'ransom encryption detected; suspicious exe'}, 'persona': 'soc'})
    print('ENQUEUED', tid)
