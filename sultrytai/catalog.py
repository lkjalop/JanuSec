import json
from pathlib import Path
from typing import List, Dict, Any

CATALOG_PATH = Path(__file__).parent.parent / 'sultry_prd' / 'factors_catalog' / 'full' / 'factors_catalog_full.json'

class FactorCatalog:
    def __init__(self, path: Path = CATALOG_PATH):
        self.path = path
        self.factors: List[Dict[str, Any]] = []

    def load(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            raise FileNotFoundError(f"Catalog not found: {self.path}")
        with self.path.open('r', encoding='utf-8') as f:
            self.factors = json.load(f)
        return self.factors

    def validate(self) -> List[str]:
        errors = []
        for i, f in enumerate(self.factors):
            if 'name' not in f:
                errors.append(f'factor[{i}] missing name')
            if 'domain' not in f:
                errors.append(f'factor[{i}] missing domain')
            if 'severity' not in f:
                errors.append(f'factor[{i}] missing severity')
        return errors

    def find_by_domain(self, domain: str) -> List[Dict[str, Any]]:
        return [f for f in self.factors if f.get('domain') == domain]
