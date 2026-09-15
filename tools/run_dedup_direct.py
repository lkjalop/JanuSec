import os
import sys
import time

# Ensure test environment variables are set as the test expects
os.environ.setdefault('ALERTS_API_KEYS', 'testkey')
os.environ.setdefault('ALERT_DEDUP_TTL_SECONDS', '1')

def main():
    try:
        # Import the test module and run the test function directly
        import importlib
        tm = importlib.import_module('tests.test_dedup_ttl')
        # Re-apply env vars used inside test
        os.environ['ALERT_DEDUP_TTL_SECONDS'] = '1'
        os.environ['ALERT_DEDUP_GRACE_SECONDS'] = '0.25'
        print('Running dedup test directly...')
        tm.test_dedup_suppression_and_expiry()
        print('DEDUP TEST: PASS')
        with open('tools/dedup_result.txt','w',encoding='utf-8') as fh:
            fh.write('PASS')
        return 0
    except AssertionError as ae:
        print('DEDUP TEST: FAIL (assertion)')
        with open('tools/dedup_result.txt','w',encoding='utf-8') as fh:
            fh.write('FAIL: ' + str(ae))
        raise
    except Exception as exc:
        print('DEDUP TEST: ERROR', exc)
        with open('tools/dedup_result.txt','w',encoding='utf-8') as fh:
            fh.write('ERROR: ' + repr(exc))
        raise

if __name__ == '__main__':
    sys.exit(main())
