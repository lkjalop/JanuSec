#!/usr/bin/env python3
"""Run ForensicLogGapDetector once (DB-less) to produce local logs for smoke testing."""
import asyncio
import logging
import os

from src.monitoring.forensic_log_gap_detector import ForensicLogGapDetector


def setup_logging():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    logging.getLogger('asyncio').setLevel(logging.WARNING)


async def main():
    setup_logging()
    db = None
    alert_manager = None
    # ensure DEFAULT_TENANT exists for DB-less runs
    os.environ.setdefault('DEFAULT_TENANT', 'default')
    detector = ForensicLogGapDetector(db=db, alert_manager=alert_manager, check_interval_seconds=1)
    print('Default tenant:', os.getenv('DEFAULT_TENANT', 'default'))
    await detector.check_all_tenants()


if __name__ == '__main__':
    asyncio.run(main())
