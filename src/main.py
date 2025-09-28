"""Platform entrypoint delegating to orchestrator package."""
from __future__ import annotations

import asyncio
import logging

from orchestrator import ProcessingResult, SecurityOrchestrator

__all__ = ['SecurityOrchestrator', 'ProcessingResult', 'main']


async def main() -> None:
    orchestrator = SecurityOrchestrator()
    try:
        await orchestrator.initialize()
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        await orchestrator.shutdown()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
