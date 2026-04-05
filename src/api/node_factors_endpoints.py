from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/v1/graph/node", tags=["graph-node-factors"])

@router.get("/{node_id}/factors")
async def node_factors(node_id: str):
    from src.api.app import app
    hg = getattr(app, 'GLOBAL_HOPGRAPH', None)
    if hg is None:
        raise HTTPException(status_code=503, detail='hopgraph_unavailable')
    # Direct lookup; node ids may include ':' so accept raw path param
    if node_id not in hg.nodes:
        raise HTTPException(status_code=404, detail='node_not_found')
    factors = hg.get_node_factors(node_id)
    return {
        'node_id': node_id,
        'factor_count': len(factors),
        'factors': sorted(factors)
    }

__all__ = ["router"]
