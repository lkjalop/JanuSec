from __future__ import annotations
import time
from src.pipeline.runner import run_once

def main():
    while True:
        try:
            run_once()
        except Exception as e:
            print('runner error', e)
        time.sleep(10)

if __name__ == '__main__':
    main()
