"""Run a simple sandbox consumer loop that processes pending queue items."""
import time
from src.workers.sandbox_consumer import process_once


def main():
    print('starting sandbox worker (press Ctrl-C to stop)')
    try:
        while True:
            res = process_once()
            if res is None:
                time.sleep(2)
                continue
            print('processed:', res)
            time.sleep(0.5)
    except KeyboardInterrupt:
        print('stopping')


if __name__ == '__main__':
    main()
