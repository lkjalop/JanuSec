from fastapi import APIRouter, BackgroundTasks
from datetime import datetime
from typing import Optional

router = APIRouter()


@router.post('/collectors/run')
async def run_collectors(background: BackgroundTasks, since: Optional[str] = None, mock: bool = True):
    """Trigger collectors run in background (demo/smoke)."""
    from src.modules.collectors.runner import run_collectors_sync

    def _job():
        try:
            run_collectors_sync(since=datetime.utcnow(), mock=mock)
        except Exception:
            pass

    background.add_task(_job)
    return {'status': 'scheduled', 'mock': bool(mock)}


__all__ = ["router"]
