from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class MLModelProvenance:
    model_id: str
    model_name: str
    source: str
    training_data: List[str]
    fine_tuning_history: List[Dict[str, Any]]
    weights_checksum: str
    model_card: Dict[str, Any]
    risk_score: float = 0.0

def assess_provenance(prov: MLModelProvenance) -> Dict[str, Any]:
    score = 0.0
    issues = []
    if prov.source not in {'huggingface', 'internal', 'github'}:
        issues.append('unknown_source')
        score += 0.25
    if not prov.weights_checksum:
        issues.append('no_weights_checksum')
        score += 0.30
    return {'issues': issues, 'score': min(score, 1.0)}
