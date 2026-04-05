from datetime import datetime, timedelta
from typing import List
import asyncio

from src.modules.collectors.proofpoint_collector import ProofpointTAPCollector
from src.modules.collectors.mimecast_collector import MimecastCollector


class CollectorsRunner:
    def __init__(self):
        self.pp = ProofpointTAPCollector()
        self.mc = MimecastCollector()

    async def run_once(self, since: datetime = None, mock: bool = True) -> List[dict]:
        since = since or (datetime.utcnow() - timedelta(hours=1))
        tasks = [self.pp.collect_threats(since, mock=mock), self.mc.collect_threats(since, mock=mock)]
        results = await asyncio.gather(*tasks)
        # flatten
        events = []
        for res in results:
            events.extend(res)
        return events


def run_collectors_sync(since: datetime = None, mock: bool = True):
    runner = CollectorsRunner()
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        events = loop.run_until_complete(runner.run_once(since=since, mock=mock))
    finally:
        try:
            loop.close()
        finally:
            try:
                asyncio.set_event_loop(None)
            except Exception:
                pass
    return events


__all__ = ["CollectorsRunner", "run_collectors_sync"]
