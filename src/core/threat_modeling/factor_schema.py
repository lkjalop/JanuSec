from __future__ import annotations
"""Factor mapping schema scaffolding.

Provides light-weight dataclasses & utilities to validate that factor taxonomy
entries include required multi-framework mappings. This avoids importing heavy
modules during validation scripts and keeps concerns separated from the
large static map in `factor_taxonomy`.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any

REQUIRED_KEYS = ['stride','dread','maestro','mitre','pasta_stage','cvss','controls']

@dataclass(frozen=True)
class FactorMapping:
    name: str
    stride: List[str] = field(default_factory=list)
    dread: Dict[str, float] = field(default_factory=dict)
    maestro: List[str] = field(default_factory=list)
    mitre: List[str] = field(default_factory=list)
    pasta_stage: List[int] = field(default_factory=list)
    cvss: Dict[str, Any] = field(default_factory=dict)
    controls: List[str] = field(default_factory=list)

    @property
    def has_minimum(self) -> bool:
        return all([
            bool(self.stride), bool(self.dread), bool(self.maestro), bool(self.mitre),
            bool(self.pasta_stage), bool(self.cvss), bool(self.controls)
        ])


def build_factor_mapping(name: str, raw: Dict[str, Any]) -> FactorMapping:
    return FactorMapping(
        name=name,
        stride=list(raw.get('stride') or []),
        dread=dict(raw.get('dread') or {}),
        maestro=list(raw.get('maestro') or []),
        mitre=list(raw.get('mitre') or []),
        pasta_stage=list(raw.get('pasta_stage') or []),
        cvss=dict(raw.get('cvss') or {}),
        controls=list(raw.get('controls') or []),
    )


def validate_factor_map(factor_map: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Validate that each factor has required framework keys.

    Returns a summary dictionary with coverage counts & list of issues.
    Unknown or synthetic correlation-only factors are allowed to miss some keys.
    """
    issues = []
    coverage_counts = {k: 0 for k in REQUIRED_KEYS}
    total = len(factor_map)
    for name, meta in factor_map.items():
        for k in REQUIRED_KEYS:
            if k in meta and meta[k]:
                coverage_counts[k] += 1
        missing = [k for k in REQUIRED_KEYS if not meta.get(k)]
        # Allow synthetic correlation / meta factors to skip CVSS & pasta_stage gracefully
        if missing and not name.startswith(('multi_','entity_','mapping_','corr_','meta:')):
            issues.append({'factor': name, 'missing': missing})
    pct = {k: round(coverage_counts[k] / max(1,total) * 100, 2) for k in coverage_counts}
    return {
        'total_factors': total,
        'coverage_percent': pct,
        'issues': issues,
        'issues_count': len(issues)
    }

__all__ = ['FactorMapping','build_factor_mapping','validate_factor_map','REQUIRED_KEYS']
