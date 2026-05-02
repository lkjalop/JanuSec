"""Orchestrator — runs the full enriched executive summary pipeline.

Called from exec_summary_endpoints.py after the deterministic backbone.
Adds: TemporalRAG context, belief trajectories, per-cluster narratives,
structured citation + validation, assessment rollup, persona adapters.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Optional

from .belief_trajectory import extract_belief_trajectory, format_trajectory_oneliner
from .evidence_frame import retrieve_evidence_frame
from .grounding_validator import validate_claims
from .narrative_synthesis import synthesize_cluster_narrative
from .persona_adapters import adapt_all_personas
from .rollup_synthesis import synthesize_rollup
from .schemas import ExecSummaryResult
from .verdict_reasoning import derive_verdict_reasoning

logger = logging.getLogger(__name__)


async def run_enriched_pipeline(
    assessment_id: str,
    assessment: dict,
    sorted_clusters: list[dict],
    llm_func: Optional[Any] = None,
    model: str = 'qwen3:14b',
    deterministic_texts: Optional[dict[str, str]] = None,
    max_clusters: int = 10,
    personas: Optional[list[str]] = None,
    tenant: str = 'default',
    rag_window_seconds: int = 7200,
    quality_mode: str = 'standard',
    persona_llm: bool = False,
    persona_subset: Optional[list[str]] = None,
) -> dict:
    """Run the full enriched pipeline and return additional fields for the result dict.

    Args:
        assessment_id: Assessment identifier.
        assessment: Full assessment dict.
        sorted_clusters: Pre-sorted cluster list (descending rank).
        llm_func: Synchronous llm.generate function (or None for deterministic only).
        model: LLM model name.
        deterministic_texts: {cluster_id: deterministic_narrative} from attack chain builder.
        max_clusters: Cap on clusters to process.
        personas: List of persona keys to generate (None = all).
        tenant: Tenant ID for TemporalRAG.
        rag_window_seconds: Time window for evidence retrieval.

    Returns:
        dict with keys: cluster_summaries, belief_trajectories,
        temporal_rag_context, rollup_summary, rollup_provenance,
        persona_summaries, pipeline_ran.
    """
    if not sorted_clusters:
        return {
            'cluster_summaries': [],
            'belief_trajectories': {},
            'temporal_rag_context': {},
            'rollup_summary': '',
            'rollup_provenance': 'no_clusters',
            'persona_summaries': {},
            'pipeline_ran': True,
            'pipeline_failures': [],
        }

    deterministic_texts = deterministic_texts or {}
    clusters_to_process = sorted_clusters[:max_clusters]
    # Phase 2 — surface LLM/timeout failures so the UI can show a banner
    # instead of silently rendering the deterministic fallback as if it were
    # the LLM result.
    pipeline_failures: list[dict] = []

    # ── Phase 1: Belief trajectories + evidence frames + verdict reasoning ──
    trajectories = {}
    evidence_frames = {}
    verdict_reasonings = {}
    for cluster in clusters_to_process:
        cid = str(cluster.get('cluster_id', ''))

        # Belief trajectory
        traj = extract_belief_trajectory(
            cluster_id=cid,
            tenant_id=tenant,
            assessment=assessment,
        )
        trajectories[cid] = traj

        # Evidence frame (TemporalRAG)
        cluster_rows = _get_cluster_rows(cluster, assessment)
        ef = retrieve_evidence_frame(
            cluster=cluster,
            rows=cluster_rows,
            tenant=tenant,
            top_k=5,
            window_seconds=rag_window_seconds,
        )
        evidence_frames[cid] = ef

        # Verdict reasoning — grader scores + counter-hypotheses
        vr = derive_verdict_reasoning(cluster, cluster_rows, assessment)
        verdict_reasonings[cid] = vr

    # ── Phase 2: Per-cluster narrative synthesis ─────────────────────────
    cluster_narratives = []
    for cluster in clusters_to_process:
        cid = str(cluster.get('cluster_id', ''))
        det_text = deterministic_texts.get(cid, '')
        traj = trajectories.get(cid)
        ef = evidence_frames.get(cid)
        vr = verdict_reasonings.get(cid)

        # LLM calls are synchronous — offload to thread
        if llm_func:
            try:
                # Phase 3 — high-quality CoT path gets a longer timeout
                # because it makes two LLM calls.
                _cot_timeout = 180 if quality_mode == 'high' else 60
                cn = await asyncio.wait_for(
                    asyncio.to_thread(
                        synthesize_cluster_narrative,
                        cluster, assessment, traj, ef, det_text, llm_func, model, vr,
                        quality_mode,
                    ),
                    timeout=_cot_timeout,
                )
            except asyncio.TimeoutError as exc:
                logger.warning('cluster narrative LLM timeout for %s after 60s', cid)
                pipeline_failures.append({
                    'stage':      'cluster_narrative',
                    'cluster_id': cid,
                    'reason':     'timeout',
                    'detail':     '60s budget exceeded',
                    'fallback':   'deterministic',
                })
                cn = synthesize_cluster_narrative(
                    cluster, assessment, traj, ef, det_text, None, model, vr,
                )
            except Exception as exc:
                logger.warning('cluster narrative LLM failed for %s: %s', cid, exc)
                pipeline_failures.append({
                    'stage':      'cluster_narrative',
                    'cluster_id': cid,
                    'reason':     type(exc).__name__,
                    'detail':     str(exc)[:240],
                    'fallback':   'deterministic',
                })
                cn = synthesize_cluster_narrative(
                    cluster, assessment, traj, ef, det_text, None, model, vr,
                )
        else:
            cn = synthesize_cluster_narrative(
                cluster, assessment, traj, ef, det_text, None, model, vr,
            )

        # Validate claims against cluster evidence
        valid_row_ids = set(
            int(r) for r in (cluster.get('row_refs') or [])
            if isinstance(r, (int, str)) and str(r).isdigit()
        )
        cn = validate_claims(cn, valid_row_ids)

        # ── Control-witness attachment (MITRE → compliance mapping) ───────
        # Attach control witnesses so the compliance persona can render
        # control_failures, cross_framework_evidence and regulatory triggers.
        # Uses MITRE-based mapping when technique IDs exist in rows, falls back
        # to keyword matching on the deterministic text when rows lack MITRE IDs.
        try:
            from src.core.verdict_engine import attach_control_witnesses
            cluster_rows = _get_cluster_rows(cluster, assessment)
            attach_control_witnesses(cluster, cluster_rows)
            # Keyword-based fallback: if MITRE mapping produced no witnesses,
            # synthesise witnesses from DREAD/deterministic text keywords so the
            # compliance persona is never completely empty.
            if not cluster.get('control_witnesses'):
                try:
                    from src.prefill.compliance_tags import derive_controls_breached
                    det_text_for_kw = deterministic_texts.get(cid) or ''
                    kw_controls = derive_controls_breached({'narrative': det_text_for_kw})
                    if kw_controls:
                        synth_witnesses: dict = {}
                        for ctrl in kw_controls:
                            cid_ctrl = ctrl['control_id']
                            synth_witnesses[cid_ctrl] = {
                                'control_id':    cid_ctrl,
                                'control_name':  ctrl['control_name'],
                                'framework':     ctrl['framework'],
                                'rows':          [],
                                'mitre':         [],
                                'sources':       ['keyword_match'],
                                'witness_count': 0,
                                'downgraded':    False,
                                'derivation':    'keyword_fallback',
                            }
                        cluster['control_witnesses'] = synth_witnesses
                        logger.info(
                            'control_witnesses cluster_id=%s keyword_fallback controls=%d',
                            cid, len(synth_witnesses),
                        )
                except Exception as kw_exc:
                    logger.debug('control_witnesses keyword fallback failed for %s: %s', cid, kw_exc)
            else:
                logger.info(
                    'control_witnesses cluster_id=%s mitre_mapped controls=%d',
                    cid, len(cluster.get('control_witnesses', {})),
                )
        except Exception as cw_exc:
            logger.warning('control_witnesses attachment failed for %s: %s', cid, cw_exc)

        # Copy witnesses onto the ClusterNarrative object so they survive model_dump()
        cw = cluster.get('control_witnesses') or {}
        if cw:
            cn.control_witnesses = cw

        cluster_narratives.append(cn)

    # ── Phase 3: Assessment-level rollup ──────────────────────────────────
    total_rows = (
        (assessment.get('evidence_store') or {}).get('row_count')
        or assessment.get('rows_processed')
        or len(assessment.get('normalized_rows') or assessment.get('rows') or [])
    )
    assessment_verdict = str(
        assessment.get('overall_verdict') or assessment.get('verdict') or 'UNCERTAIN'
    ).upper()

    if llm_func:
        try:
            rollup_text, rollup_prov = await asyncio.wait_for(
                asyncio.to_thread(
                    synthesize_rollup,
                    cluster_narratives, assessment_verdict, total_rows, llm_func, model,
                ),
                timeout=60,
            )
        except asyncio.TimeoutError:
            logger.warning('rollup LLM timeout after 60s')
            pipeline_failures.append({
                'stage':   'rollup',
                'reason':  'timeout',
                'detail':  '60s budget exceeded',
                'fallback':'deterministic',
            })
            rollup_text, rollup_prov = synthesize_rollup(
                cluster_narratives, assessment_verdict, total_rows, None, model,
            )
        except Exception as exc:
            logger.warning('rollup LLM failed: %s', exc)
            pipeline_failures.append({
                'stage':   'rollup',
                'reason':  type(exc).__name__,
                'detail':  str(exc)[:240],
                'fallback':'deterministic',
            })
            rollup_text, rollup_prov = synthesize_rollup(
                cluster_narratives, assessment_verdict, total_rows, None, model,
            )
    else:
        rollup_text, rollup_prov = synthesize_rollup(
            cluster_narratives, assessment_verdict, total_rows, None, model,
        )

    # ── Phase 4: Persona adapters ─────────────────────────────────────────
    # When persona_llm=True, rewrite each persona narrative via the LLM.
    # persona_subset limits to specific personas (default: all) to control
    # LLM call count (7 personas × N clusters can be expensive).
    active_personas = persona_subset if persona_subset else personas
    _persona_llm_func = llm_func if (persona_llm and llm_func) else None
    if _persona_llm_func:
        logger.info(
            'persona_llm enabled for %s personas on %d clusters',
            len(active_personas) if active_personas else 'all',
            len(cluster_narratives),
        )
    persona_summaries_raw = adapt_all_personas(
        cluster_narratives, active_personas, _persona_llm_func, model,
        clusters=clusters_to_process,
    )

    # ── Serialize ─────────────────────────────────────────────────────────
    cluster_summaries = [cn.model_dump() for cn in cluster_narratives]
    belief_trajectories = {
        cid: traj.model_dump() for cid, traj in trajectories.items()
    }
    temporal_rag_context = {
        cid: ef.model_dump() for cid, ef in evidence_frames.items()
    }
    persona_summaries = {
        persona: [pn.model_dump() for pn in pn_list]
        for persona, pn_list in persona_summaries_raw.items()
    }

    return {
        'cluster_summaries': cluster_summaries,
        'belief_trajectories': belief_trajectories,
        'temporal_rag_context': temporal_rag_context,
        'verdict_reasoning': verdict_reasonings,
        'rollup_summary': rollup_text,
        'rollup_provenance': rollup_prov,
        'persona_summaries': persona_summaries,
        'pipeline_ran': True,
        'pipeline_failures': pipeline_failures,
    }


def _get_cluster_rows(cluster: dict, assessment: dict) -> list[dict]:
    """Get normalized rows for a cluster from the assessment."""
    row_refs = cluster.get('row_refs') or []
    all_rows = (
        assessment.get('normalized_rows')
        or assessment.get('evidence_rows')
        or assessment.get('rows')
        or []
    )
    row_map = {r.get('row_index', i): r for i, r in enumerate(all_rows)}
    return [row_map[ref] for ref in row_refs if ref in row_map]
