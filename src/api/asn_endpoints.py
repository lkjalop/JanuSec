from fastapi import APIRouter
import time
from src.live import asn_stats

router = APIRouter(prefix='/api/v1/asn')


@router.get('/rarity/{asn}')
async def asn_rarity(asn: str):
    try:
        score = asn_stats.rarity(asn)
        return {'asn': asn, 'rarity': score}
    except Exception:
        return {'asn': asn, 'rarity': 0.0}


@router.get('/distinct')
async def asn_distinct():
    return {'distinct': asn_stats.get_current_asn_distinct()}
