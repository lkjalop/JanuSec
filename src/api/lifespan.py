import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from src.core.metrics.connectors_metrics import queue_depth

@asynccontextmanager
async def app_lifespan(app: FastAPI):
    # Initialize bounded queues for connectors
    app.state.connector_queues = {
        "crowdstrike": asyncio.Queue(maxsize=1000),
        "sentinel": asyncio.Queue(maxsize=1000),
        "splunk": asyncio.Queue(maxsize=1000),
    }
    try:
        yield
    finally:
        # Drain queues on shutdown if needed
        for name, q in app.state.connector_queues.items():
            queue_depth.labels(name).set(q.qsize())
