"""Simple CLI to run token rotation worker for development/demo."""
import asyncio
import logging
from src.workers.token_rotation import TokenRotationWorker

logging.basicConfig(level=logging.INFO)

async def main():
    w = TokenRotationWorker(interval=60)
    try:
        await w.run()
    except KeyboardInterrupt:
        w.stop()

if __name__ == '__main__':
    asyncio.run(main())
