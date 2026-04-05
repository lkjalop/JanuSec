from fastapi import APIRouter, HTTPException
from starlette.requests import Request
import json
from pathlib import Path

router = APIRouter()

SEED_PATH = Path(__file__).resolve().parent.parent.parent / 'scripts' / 'demo_seed.json'


def _load_seed():
    try:
        if not SEED_PATH.exists():
            raise FileNotFoundError
        with SEED_PATH.open('r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        return None


@router.get('/api/v1/hunt/overview')
async def hunt_overview(request: Request):
    data = _load_seed()
    if not data:
        raise HTTPException(status_code=404, detail='no_demo_seed')
    return {'overview': data.get('overview', {}), 'generated_at': data.get('generated_at')}


@router.get('/api/v1/hunt/metrics')
async def hunt_metrics(request: Request):
    data = _load_seed()
    if not data:
        raise HTTPException(status_code=404, detail='no_demo_seed')
    return {'metrics': data.get('metrics', {}), 'samples': data.get('samples', {})}
