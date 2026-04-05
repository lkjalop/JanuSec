from fastapi import APIRouter
from src.core.factor_metadata import list_all_factors

router = APIRouter()


@router.get('/api/v1/factors')
def get_factors():
    """Return canonical factor taxonomy and metadata for frontend consumption."""
    return list_all_factors()

__all__ = ['router']
