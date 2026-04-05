from fastapi import APIRouter
from src.repositories import ab_test_repo

router = APIRouter()


@router.get("/api/v1/abtests/active")
async def get_active_tests():
    rows = await ab_test_repo.list_active()
    return {"tests": rows}


@router.get("/api/v1/abtests")
async def get_all_tests():
    rows = await ab_test_repo.list_all()
    return {"tests": rows}
