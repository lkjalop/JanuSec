from __future__ import annotations
import json, os
from typing import Any, Dict, List
try:
    from jsonschema import validate, ValidationError  # type: ignore
    _HAVE_JSONSCHEMA = True
except Exception:
    validate = None  # type: ignore
    ValidationError = Exception  # type: ignore
    _HAVE_JSONSCHEMA = False

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), 'catalog_schema.json')

def _load_schema() -> Dict[str, Any]:
    try:
        with open(SCHEMA_PATH, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        return {}

_SCHEMA = _load_schema()

def validate_rule_doc(doc: Dict[str, Any]) -> List[str]:
    errs: List[str] = []
    if _HAVE_JSONSCHEMA and validate is not None:
        try:
            validate(instance=doc, schema=_SCHEMA)
        except ValidationError as e:
            errs.append(str(e))
        except Exception as e:
            errs.append(str(e))
    else:
        # Minimal fallback validation for environments without jsonschema.
        # Check presence of a few required top-level fields and semver-like version.
        required = ('id', 'version', 'name')
        for k in required:
            if k not in (doc or {}):
                errs.append(f'missing_required:{k}')
        ver = (doc or {}).get('version')
        try:
            if isinstance(ver, str):
                parts = ver.split('.')
                if len(parts) != 3 or not all(p.isdigit() for p in parts):
                    errs.append('invalid_version_format')
            else:
                errs.append('invalid_version_format')
        except Exception:
            errs.append('invalid_version_format')
    return errs

def load_rules_from_dir(path: str) -> List[Dict[str, Any]]:
    out = []
    if not os.path.isdir(path):
        return out
    for fn in os.listdir(path):
        if not fn.endswith('.json') and not fn.endswith('.yaml') and not fn.endswith('.yml'):
            continue
        p = os.path.join(path, fn)
        try:
            with open(p, 'r', encoding='utf-8') as fh:
                if fn.endswith('.json'):
                    doc = json.load(fh)
                else:
                    import yaml
                    doc = yaml.safe_load(fh)
            out.append(doc)
        except Exception:
            continue
    return out
