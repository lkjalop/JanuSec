"""Simple daily aggregator runner for precision metrics.

Usage: python -m scripts.daily_precision_aggregator
"""
import asyncio
import time
from datetime import datetime
import os

from src.repositories.precision_aggregator import PrecisionAggregator


async def main():
    agg = PrecisionAggregator()
    await agg.init_db()
    # default: aggregate for yesterday
    today = int(time.time())
    yesterday = today - 86400
    # normalize to midnight UTC
    day = int(datetime.utcfromtimestamp(yesterday).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    print('Aggregating day', day)
    await agg.aggregate_day(day, precision_repo_path=os.environ.get('PRECISION_REPO_PATH', 'data/precision_metrics.jsonl'))


if __name__ == '__main__':
    asyncio.run(main())
