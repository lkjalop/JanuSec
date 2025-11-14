"""Generate `threat_dimensions.json` from `framework_catalog.py` and `artifact_factors.py`.
This script maps factors in `artifact_factors.FACTOR_WEIGHTS` to framework entries if available.
"""
from __future__ import annotations
import json, os

ROOT = os.path.dirname(__file__)
CATALOG_PATH = os.path.join(ROOT, 'framework_catalog.py')
FACTORS_PATH = os.path.join(ROOT, 'artifact_factors.py')
OUT_PATH = os.path.join(ROOT, 'threat_dimensions.json')

# Import by path
import importlib.util

def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

catalog = load_module(CATALOG_PATH, 'framework_catalog')
factors = load_module(FACTORS_PATH, 'artifact_factors')

mapping = {}
for factor_name in getattr(factors, 'FACTOR_WEIGHTS', {}).keys():
    entry = {'mitre': [], 'stride': [], 'pasta_stage': None, 'controls': [], 'confidence': 'medium'}
    # try to find matching catalog entries
    for k, v in getattr(catalog, 'FRAMEWORK_CATALOG', {}).items():
        mitre = v.get('mitre', [])
        stride = v.get('stride', [])
        # simple heuristics: if factor_name token appears in key or in mitre/stride strings
        if factor_name in k or any(factor_name in str(x).lower() for x in mitre + stride):
            entry['mitre'] = list(set(entry['mitre'] + mitre))
            entry['stride'] = list(set(entry['stride'] + stride))
            entry['confidence'] = 'high'
    mapping[factor_name] = entry

with open(OUT_PATH, 'w', encoding='utf-8') as fh:
    json.dump(mapping, fh, indent=2)

print('Wrote', OUT_PATH)
