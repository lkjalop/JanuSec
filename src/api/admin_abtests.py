from fastapi import APIRouter, HTTPException, Depends
from src.repositories import ab_test_repo
from src.security.roles import require_roles

router = APIRouter(dependencies=[Depends(require_roles('admin'))])


@router.post('/api/v1/abtests/{test_id}/start')
async def start_abtest(test_id: str):
    existing = await ab_test_repo.get_test(test_id)
    if not existing:
        raise HTTPException(status_code=404, detail='abtest not found')
    await ab_test_repo.set_enabled(test_id, True)
    return {'id': test_id, 'enabled': True}


@router.post('/api/v1/abtests/{test_id}/stop')
async def stop_abtest(test_id: str):
    existing = await ab_test_repo.get_test(test_id)
    if not existing:
        raise HTTPException(status_code=404, detail='abtest not found')
    await ab_test_repo.set_enabled(test_id, False)
    return {'id': test_id, 'enabled': False}
