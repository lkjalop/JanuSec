from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from typing import List, Any, Dict

from .ingest_store import create_event_for_row
# Use the shared auth dependency implemented in `security.auth`
from security.auth import auth_dependency, require_scopes

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"])


class RowIn(BaseModel):
    row_index: int
    raw: Dict[str, Any]


class IngestResult(BaseModel):
    row_index: int
    event_id: str


@router.post("/csv_rows", response_model=List[IngestResult])
async def ingest_csv_rows(rows: List[RowIn], request: Request, _auth=Depends(require_scopes())):
    if not rows:
        raise HTTPException(status_code=400, detail="empty rows")
    out = []
    for r in rows:
        eid = create_event_for_row(r.raw)
        out.append({"row_index": r.row_index, "event_id": eid})
    return out
