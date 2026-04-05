"""Simple repo for persona risk appetite profiles.

Profiles stored as JSON under data/risk_profiles.json for demo. Production
should use DB + admin endpoints.
"""
from pathlib import Path
import json

_P = Path('data') / 'risk_profiles.json'
_P.parent.mkdir(parents=True, exist_ok=True)

_DEFAULT = {
    'executive': {'min_confidence': 0.6, 'impact_cap_usd': 50000, 'require_cost_summary': True},
    'soc_analyst': {'min_confidence': 0.0, 'impact_cap_usd': None, 'require_cost_summary': False},
    'compliance': {'min_confidence': 0.7, 'impact_cap_usd': None, 'require_cost_summary': True},
    'threat_hunter': {'min_confidence': 0.0, 'impact_cap_usd': None, 'require_cost_summary': False},
    'mssp': {'min_confidence': 0.0, 'impact_cap_usd': None, 'require_cost_summary': False},
}

def load_profiles():
    try:
        if _P.exists():
            return json.loads(_P.read_text(encoding='utf-8'))
    except Exception:
        pass
    return _DEFAULT

def save_profiles(profiles: dict):
    try:
        _P.write_text(json.dumps(profiles), encoding='utf-8')
        return True
    except Exception:
        return False

__all__ = ['load_profiles', 'save_profiles']
