"""Incident dataclass — the unit of output from the extraction module."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class CoherenceWarning(Enum):
    NONE = 'none'
    MIXED_CORRELATIONS = 'mixed_correlations'
    SINGLE_CHAIN_INFERRED = 'single_chain_inferred'
    TEMPORAL_ANOMALY = 'temporal_anomaly'


@dataclass
class Incident:
    incident_id: str
    name: str
    source_cluster_ids: List[str]
    row_refs: List[int]
    entities: Dict[str, List[str]]
    mitre_techniques: List[str]
    kill_chain_phases: List[str]
    start_time: str
    end_time: str
    severity: str
    confidence: float
    coherence_score: float
    coherence_warning: CoherenceWarning
    source_types: List[str]
    split_rationale: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            'incident_id': self.incident_id,
            'name': self.name,
            'source_cluster_ids': self.source_cluster_ids,
            'row_refs': self.row_refs,
            'entities': self.entities,
            'mitre_techniques': self.mitre_techniques,
            'kill_chain_phases': self.kill_chain_phases,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'severity': self.severity,
            'confidence': self.confidence,
            'coherence_score': self.coherence_score,
            'coherence_warning': self.coherence_warning.value,
            'source_types': self.source_types,
            'split_rationale': self.split_rationale,
        }
