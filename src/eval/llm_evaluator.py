import time
from typing import List, Dict, Any
from src.repositories.llm_claims_repo import list_unadjudicated, stats, mark_adjudication


def sample_and_report(limit: int = 50) -> Dict[str, Any]:
    rows = list_unadjudicated(limit)
    # Return a small sample for adjudicators
    return {'count': len(rows), 'sample': rows}


def compute_precision_report() -> Dict[str, Any]:
    s = stats()
    return s


def adjudicate_batch(decision_pairs: List[Dict[str, Any]]):
    # decision_pairs: list of {'claim_id': int, 'is_correct': bool}
    for p in decision_pairs:
        try:
            mark_adjudication(int(p['claim_id']), bool(p['is_correct']))
        except Exception:
            pass
    return compute_precision_report()


if __name__ == '__main__':
    print('LLM evaluator')
    print('precision report:', compute_precision_report())
