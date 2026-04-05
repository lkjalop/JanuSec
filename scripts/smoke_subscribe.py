import redis
import time

CH = 'assessment:events:smoke-assess-1'

if __name__ == '__main__':
    rc = redis.from_url('redis://127.0.0.1:6379/0')
    p = rc.pubsub()
    p.subscribe(CH)
    print('SUBSCRIBED', CH)
    start = time.time()
    cnt = 0
    for m in p.listen():
        print('MSG', m)
        cnt += 1
        if cnt >= 5 or time.time() - start > 60:
            break
    print('DONE')
