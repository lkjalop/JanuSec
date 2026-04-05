from fastapi import APIRouter, HTTPException
from src.ml.closed_loop_manager import ClosedLoopManager

router = APIRouter(prefix='/api/v1/weight_staging', tags=['weight_staging'])
_CLM = ClosedLoopManager()


@router.get('/pending')
async def list_pending():
    lst = await _CLM.list_pending()
    return {'pending': lst}


@router.post('/simulate/{proposal_id}')
def simulate(proposal_id: int):
    try:
        pend = asyncio.get_event_loop().run_until_complete(_CLM.list_pending())
    except Exception:
        pend = []
    p = next((x for x in pend if int(x['id']) == int(proposal_id)), None)
    if not p:
        raise HTTPException(status_code=404, detail='proposal_not_found')
    sim = _CLM.simulate_proposal(p)
    return {'sim': sim}


@router.post('/apply/{proposal_id}')
def apply_proposal(proposal_id: int):
    res = _CLM.apply_proposal_if_safe(proposal_id)
    if not res.get('ok'):
        raise HTTPException(status_code=400, detail=res)
    return res
from fastapi import APIRouter, HTTPException, Body
from src.repositories.weight_staging_repo import WeightStagingRepo
from src.ml.closed_loop_manager import ClosedLoopManager
from src.repositories.weight_proposals_repo import persist_proposal, write_replay_report, get_proposal, list_recent, mark_applied as mark_proposal_applied

router = APIRouter(prefix='/api/v1/weight_staging', tags=['weight_staging'])


@router.get('/pending')
async def list_pending():
    repo = WeightStagingRepo()
    return await repo.list_pending()


@router.get('/simulate/{proposal_id}')
async def simulate(proposal_id: int):
    clm = ClosedLoopManager()
    pend = await clm.staging.list_pending()
    p = next((x for x in pend if x['id'] == proposal_id), None)
    if not p:
        raise HTTPException(status_code=404, detail='proposal_not_found')
    # run replay evaluation and persist report to proposals repo
    sim = clm.simulate_proposal(p)
    try:
        from src.ml.replay_eval import ReplayEvaluator
        rev = ReplayEvaluator()
        rpt = rev.replay(p.get('weights') or p.get('proposed_weights') or {}, sample_limit=2000)
        write_replay_report(proposal_id, rpt)
        sim['replay_report'] = rpt
    except Exception:
        sim['replay_report'] = None
    return sim


@router.post('/persist', status_code=201)
async def persist(payload: dict = Body(...)):
    # Persist proposal metadata into proposals DB for traceability
    rule = payload.get('rule_id') or payload.get('rule')
    proposer = payload.get('proposer') or payload.get('actor')
    candidate = payload.get('weights') or payload.get('candidate') or {}
    ab_test = payload.get('ab_test_id')
    pid = persist_proposal(rule, proposer, candidate, ab_test)
    return {'proposal_id': pid}


@router.post('/replay/{proposal_id}')
async def replay(proposal_id: int):
    p = get_proposal(proposal_id)
    if not p:
        raise HTTPException(status_code=404, detail='proposal_not_found')
    try:
        from src.ml.replay_eval import ReplayEvaluator
        rev = ReplayEvaluator()
        rpt = rev.replay(p.get('candidate') or {}, sample_limit=2000)
        write_replay_report(proposal_id, rpt)
        return {'proposal_id': proposal_id, 'replay_report': rpt}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'replay_failed:{exc}')


@router.post('/apply/{proposal_id}')
async def apply(proposal_id: int):
    clm = ClosedLoopManager()
    res = clm.apply_proposal_if_safe(proposal_id)
    if not res.get('ok'):
        raise HTTPException(status_code=400, detail=res)
    # persist applied marker
    try:
        mark_proposal_applied(proposal_id)
    except Exception:
        pass
    return res


@router.post('/rollback/{proposal_id}')
async def rollback(proposal_id: int):
    # Simple rollback: remove current candidate JSON if matching proposal_id
    import os, json
    p = get_proposal(proposal_id)
    if not p:
        raise HTTPException(status_code=404, detail='proposal_not_found')
    path = os.path.join('data', 'factor_weights_current.json')
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail='no_active_rollout')
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            cur = json.load(fh)
        if cur.get('candidate_id') != proposal_id:
            raise HTTPException(status_code=400, detail='proposal_not_active')
        os.remove(path)
        return {'ok': True, 'rolled_back': proposal_id}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'rollback_failed:{exc}')


@router.get('/proposals')
async def proposals():
    return {'proposals': list_recent(50)}


@router.get('/active_rollout')
async def active_rollout():
    try:
        from src.core.factor_rollout import get_current_weights, get_rollout_pct
        w = get_current_weights()
        p = get_rollout_pct()
        return {'weights': w, 'rollout_pct': p}
    except Exception:
        raise HTTPException(status_code=500, detail='active_rollout_failed')

