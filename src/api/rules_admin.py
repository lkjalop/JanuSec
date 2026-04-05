from __future__ import annotations
import os, json
from typing import Any, Dict
from fastapi import APIRouter, HTTPException, Depends
from src.rules.loader import validate_rule_doc, load_rules_from_dir
from src.rules.mitre_map import summarize_mitre_for_rules
from src.security.roles import require_any_role_dep

router = APIRouter(tags=['rules'], dependencies=[Depends(require_any_role_dep('admin', 'analyst'))])


@router.get('/api/v1/rules/summary')
def rules_summary():
    try:
        rules_dir = os.getenv('RULES_DIR', 'data/rules')
        rules = load_rules_from_dir(rules_dir)
        mit = summarize_mitre_for_rules(rules)
        return {'count': len(rules), 'mitre_summary': mit}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
@router.get('/api/v1/rules/validate')
def rules_validate():
    try:
        rules_dir = os.getenv('RULES_DIR', 'data/rules')
        docs = load_rules_from_dir(rules_dir)
        results = []
        for d in docs:
            errs = validate_rule_doc(d)
            results.append({'id': d.get('id'), 'name': d.get('name'), 'errors': errs})
        return {'results': results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
