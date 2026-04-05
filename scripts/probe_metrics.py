import os
import time
import traceback

def main():
    try:
        os.environ.setdefault('ENABLE_TENANT_METRICS', '1')
        os.environ.setdefault('TENANT_METRICS_HASH_BUCKETS', '5')
        from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest
        print('prometheus_client module:', __import__('prometheus_client'))
        reg = CollectorRegistry()
        print('Created registry', type(reg))
        h = Histogram('test_hist_seconds', 'test', ['depth_bucket','tenant'], registry=reg)
        c = Counter('test_counter_total', 'test', ['result','tenant'], registry=reg)
        h.labels(depth_bucket='4-6', tenant='t1').observe(0.01)
        c.labels(result='success', tenant='t1').inc()
        try:
            items = list(reg.collect())
            print('collect returned', len(items), 'items')
            print('names:', [getattr(i,'name',None) for i in items])
        except Exception as e:
            print('collect raised', e)
        try:
            txt = generate_latest(reg)
            print('generate_latest len', len(txt) if txt is not None else None)
        except Exception as e:
            print('generate_latest raised', e)
    except Exception:
        traceback.print_exc()

if __name__ == '__main__':
    main()
