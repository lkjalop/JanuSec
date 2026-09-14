"""Unified correlation rule metadata schema.

This augments the minimal execution-only `CorrelationRule` with rich
threat‑model metadata (MITRE, STRIDE, DREAD, MAESTRO, prioritization).

Design goals:
 - Pure stdlib (dataclasses + typing) to avoid new deps.
 - Forward compatible: easy to swap to Pydantic if project adopts it later.
 - Loader merges dynamic STRIDE / MAESTRO categories using existing
   factor taxonomy utilities when factors are provided.

Usage:
  from .metadata_schema import load_rule_metadata_registry
  registry = load_rule_metadata_registry()

File format (JSON list) stored in `rules_metadata.json` alongside code.
Each entry minimal required keys:
  id, name, status, mitre: {tactic, technique_id?}, factors[], dread.components,
  stride.categories (optional if factors given), priority (float), maturity_level (int)

Priority formula is not recomputed here; an external script can update
and persist recalculated values. Loader is tolerant of missing optional fields.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import json, os, logging

from src.core.threat_modeling.factor_taxonomy import aggregate_threat_model, compute_dread_score

logger = logging.getLogger(__name__)

REGISTRY_FILE = os.path.join(os.path.dirname(__file__), 'rules_metadata.json')


@dataclass
class DreadComponents:
    damage: float
    reproducibility: float
    exploitability: float
    affected_users: float
    discoverability: float
    risk_score: Optional[float] = None  # normalized (0..1) if computed


@dataclass
class RuleMetadata:
    id: str
    name: str
    status: str  # active | planned | experimental | deprecated
    mitre_tactic: str
    mitre_technique: Optional[str] = None
    factors: List[str] = field(default_factory=list)
    stride: List[str] = field(default_factory=list)
    maestro_phases: List[str] = field(default_factory=list)
    dread: Optional[DreadComponents] = None
    maturity_level: int = 1  # 1..4 progression
    prevalence_factor: float = 0.0
    coverage_gap_factor: float = 0.0
    priority: float = 0.0
    false_positive_target: float = 0.1
    logic_ref: Optional[str] = None  # path to implementation file/function
    test_vectors: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'RuleMetadata':
        dread_obj = None
        dread_in = d.get('dread')
        if isinstance(dread_in, dict):
            # Accept either nested components or flat values
            comp = dread_in.get('components') or dread_in
            try:
                dread_obj = DreadComponents(
                    damage=comp['damage'],
                    reproducibility=comp['reproducibility'],
                    exploitability=comp['exploitability'],
                    affected_users=comp['affected_users'],
                    discoverability=comp['discoverability'],
                    risk_score=dread_in.get('risk_score') or comp.get('risk_score')
                )
            except Exception:
                logger.debug('Incomplete dread components for %s', d.get('id'))
        return cls(
            id=d['id'],
            name=d.get('name', d['id']),
            status=d.get('status','planned'),
            mitre_tactic=d.get('mitre',{}).get('tactic') or d.get('mitre_tactic','unknown'),
            mitre_technique=d.get('mitre',{}).get('technique_id') or d.get('mitre_technique'),
            factors=d.get('factors',[]) or d.get('signals',[]),
            stride=d.get('stride',{}).get('categories') if isinstance(d.get('stride'), dict) else d.get('stride',[]) or [],
            maestro_phases=[p for p in (d.get('maestro',{}) or {}).get('phases',[]) if isinstance(p, str)] or [],
            dread=dread_obj,
            maturity_level=int(d.get('maestro',{}).get('maturity_level', d.get('maturity_level',1)) or 1),
            prevalence_factor=float(d.get('prevalence_factor',0.0)),
            coverage_gap_factor=float(d.get('coverage_gap_factor',0.0)),
            priority=float(d.get('priority',0.0)),
            false_positive_target=float(str(d.get('false_positive_target',0.1)).replace('<=','')),
            logic_ref=d.get('logic_ref'),
            test_vectors=d.get('test_vectors',[])
        )

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            'id': self.id,
            'name': self.name,
            'status': self.status,
            'mitre': {'tactic': self.mitre_tactic, 'technique_id': self.mitre_technique},
            'factors': self.factors,
            'stride': self.stride,
            'maestro': {'phases': self.maestro_phases, 'maturity_level': self.maturity_level},
            'prevalence_factor': round(self.prevalence_factor,3),
            'coverage_gap_factor': round(self.coverage_gap_factor,3),
            'priority': round(self.priority,2),
            'false_positive_target': self.false_positive_target,
            'logic_ref': self.logic_ref,
            'test_vectors': self.test_vectors,
        }
        if self.dread:
            d['dread'] = {
                'components': {
                    'damage': self.dread.damage,
                    'reproducibility': self.dread.reproducibility,
                    'exploitability': self.dread.exploitability,
                    'affected_users': self.dread.affected_users,
                    'discoverability': self.dread.discoverability,
                },
                'risk_score': self.dread.risk_score,
            }
        return d

    def ensure_dynamic_fields(self) -> None:
        # If stride or maestro phases missing but factors exist, recompute.
        if self.factors and (not self.stride or not self.maestro_phases or not (self.dread and self.dread.risk_score is not None)):
            agg = aggregate_threat_model(self.factors)
            if not self.stride:
                # If aggregation yields no STRIDE categories (e.g., new
                # graph-only factors or placeholders), provide a safe
                # fallback so downstream consumers and tests observe a
                # non-empty list rather than an empty value.
                self.stride = agg['stride']['categories'] or ['unknown']
            if not self.maestro_phases:
                self.maestro_phases = [p for p,_cnt in agg['maestro']['phases']]
            # Always recompute risk if absent
            if not self.dread or self.dread.risk_score is None:
                sc = compute_dread_score(self.factors)
                c = sc['components']
                if not self.dread:
                    self.dread = DreadComponents(
                        damage=c['damage'],
                        reproducibility=c['reproducibility'],
                        exploitability=c['exploitability'],
                        affected_users=c['affected_users'],
                        discoverability=c['discoverability'],
                        risk_score=sc['risk_score']
                    )
                else:
                    self.dread.risk_score = sc['risk_score']


def load_rule_metadata_registry(path: str | None = None) -> List[RuleMetadata]:
    file_path = path or REGISTRY_FILE
    if not os.path.exists(file_path):
        logger.warning('Rule metadata registry file missing: %s', file_path)
        return []
    try:
        with open(file_path,'r',encoding='utf-8') as f:
            raw = json.load(f)
        out: List[RuleMetadata] = []
        for item in raw:
            try:
                meta = RuleMetadata.from_dict(item)
                meta.ensure_dynamic_fields()
                out.append(meta)
            except Exception as e:
                logger.error('Failed to parse rule metadata entry %s: %s', item.get('id'), e)
        return out
    except Exception as e:
        logger.error('Failed loading rule metadata registry: %s', e)
        return []


def save_rule_metadata_registry(objs: List[RuleMetadata], path: str | None = None) -> None:
    file_path = path or REGISTRY_FILE
    try:
        data = [o.to_dict() for o in objs]
        with open(file_path,'w',encoding='utf-8') as f:
            json.dump(data, f, indent=2, sort_keys=False)
    except Exception as e:
        logger.error('Failed saving rule metadata registry: %s', e)


__all__ = ['RuleMetadata','DreadComponents','load_rule_metadata_registry','save_rule_metadata_registry','REGISTRY_FILE']
