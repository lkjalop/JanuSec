from __future__ import annotations

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
import json
from pathlib import Path


class RuleCondition(BaseModel):
    field: str
    op: str = Field(..., description="Operator, e.g. eq, contains, regex")
    value: Any


class RuleAction(BaseModel):
    type: str  # e.g., 'emit_factor','create_alert','enrich'
    params: Dict[str, Any] = Field(default_factory=dict)


class RuleMeta(BaseModel):
    id: str
    name: Optional[str]
    description: Optional[str]
    author: Optional[str]
    version: Optional[str]
    tags: List[str] = Field(default_factory=list)


class ConditionGroup(BaseModel):
    type: Optional[str] = None
    node_type: Optional[str] = None
    filters: List[RuleCondition] = Field(default_factory=list)
    joins: List[Dict[str, Any]] = Field(default_factory=list)
    confidence: Optional[float] = None


class DetectionRule(BaseModel):
    meta: RuleMeta
    # Backwards-compatible simple conditions
    conditions: List[RuleCondition] = Field(default_factory=list)
    # Structured condition groups (preferred)
    condition_groups: List[ConditionGroup] = Field(default_factory=list)
    joins: List[Dict[str, Any]] = Field(default_factory=list)
    actions: List[RuleAction] = Field(default_factory=list)
    score: Optional[float] = Field(default=0.0, ge=0.0, le=1.0)
    enabled: bool = True

    @field_validator('conditions', mode='after')
    def non_empty_conditions(cls, v):
        if not v:
            raise ValueError('rules must include at least one condition')
        return v


def load_rule_from_yaml(path: str | Path) -> DetectionRule:
    try:
        import yaml
    except Exception as e:
        raise RuntimeError('PyYAML is required to load rule YAML') from e
    p = Path(path)
    txt = p.read_text(encoding='utf-8')
    data = yaml.safe_load(txt)
    # Back-compat: accept flat rule format (id/title/joins/actions) and normalize to DetectionRule
    if not isinstance(data, dict):
        raise ValueError('rule YAML must contain a mapping/root object')
    # If already contains 'meta' assume current shape
    if 'meta' in data and isinstance(data.get('meta'), dict):
        return DetectionRule.model_validate(data)
    # Normalize flat format
    meta = {
        'id': str(data.get('id') or data.get('rule_id') or ''),
        'name': data.get('title') or data.get('name'),
        'description': data.get('description'),
        'author': data.get('author'),
        'version': data.get('version'),
        'tags': data.get('tags') or [],
    }
    # Conditions expected as list of dicts with keys field/op/value
    conds = data.get('conditions') or []
    condition_groups = data.get('condition_groups') or []
    # If 'conditions' is present but 'condition_groups' not, try to build a simple group
    if conds and not condition_groups:
        condition_groups = [{
            'type': 'node_property_group',
            'filters': conds,
            'joins': data.get('joins') or []
        }]
    # If no flat conditions provided but structured groups exist, expose the first group's filters
    # on the top-level `conditions` list for backwards compatibility with older runners/tests.
    if not conds and condition_groups:
        try:
            first = condition_groups[0]
            fg = first.get('filters') if isinstance(first, dict) else None
            if fg:
                conds = fg
        except Exception:
            pass
    # Actions: normalize flexible shapes into RuleAction {type, params}
    raw_actions = data.get('actions') or []
    norm_actions = []
    for a in raw_actions:
        if not isinstance(a, dict):
            continue
        # prefer explicit 'type' field
        typ = a.get('type') or a.get('id') or a.get('action') or 'create_alert'
        params = {k: v for k, v in a.items() if k not in ('type', 'id', 'action')}
        norm_actions.append({'type': typ, 'params': params})
    payload = {
        'meta': meta,
        'conditions': conds,
        'condition_groups': condition_groups,
        'joins': data.get('joins') or [],
        'actions': norm_actions,
        'enabled': data.get('enabled', True),
        'score': float(data.get('score', 0.0) or 0.0),
    }
    # Elevate any joins specified in the first condition group into top-level joins
    try:
        if not payload['joins'] and isinstance(condition_groups, list) and condition_groups:
            first = condition_groups[0]
            if isinstance(first, dict) and first.get('joins'):
                payload['joins'] = first.get('joins')
    except Exception:
        pass
    return DetectionRule.model_validate(payload)


def export_json_schema() -> Dict[str, Any]:
    """Return the JSON Schema for DetectionRule (as a dict)."""
    return DetectionRule.model_json_schema()


if __name__ == '__main__':
    import sys
    schema = export_json_schema()
    json.dump(schema, sys.stdout, indent=2)
