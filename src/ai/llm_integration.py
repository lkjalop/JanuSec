from typing import Dict, Any
from .llm_prompts import EnhancedPortScanPromptBuilder
from src.core.scoring.dread_engine import compute_dread


def build_tier1_payload(scan_event: Dict[str, Any], factors: list, dread: Dict[str, Any] | None, log_gaps: list, diamond_cluster: Dict[str, Any], inferred_motivation: Dict[str, Any], subsequent_activity: Dict[str, Any]) -> Dict[str, Any]:
    """Compose Tier1 prompt and minimal metadata for LLM invocation."""
    kill_chain_phase = scan_event.get('kill_chain_phase', 'Reconnaissance')
    # If DREAD not provided, compute from evidence (factors + artifact)
    if not dread:
        try:
            dread = compute_dread(scan_event or {}, factors or [])
        except Exception:
            dread = {'composite': 0.0, 'damage': 0, 'reproducibility': 0, 'exploitability': 0, 'affected': 0, 'discoverability': 0}
    prompt = EnhancedPortScanPromptBuilder.build_tier1_port_scan_prompt(
        scan_event=scan_event,
        factors=factors,
        dread_score=dread,
        kill_chain_phase=kill_chain_phase,
        diamond_cluster=diamond_cluster or {},
        inferred_motivation=inferred_motivation or {},
        subsequent_activity=subsequent_activity or {},
    )

    return {
        'prompt': prompt,
        'metadata': {
            'dread': dread,
            'log_gaps': log_gaps,
            'diamond_cluster': diamond_cluster,
            'inferred_motivation': inferred_motivation,
            'kill_chain_phase': kill_chain_phase,
        }
    }
