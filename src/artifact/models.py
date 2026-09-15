from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, TypedDict


class ArtifactType(str, Enum):
    EXECUTABLE = "executable"
    SCRIPT = "script"
    DOCUMENT = "document"
    BROWSER_EXTENSION = "browser_extension"
    SCHEDULED_TASK = "scheduled_task"
    WMI_CONSUMER = "wmi_consumer"
    DRIVER = "driver"
    DOWNLOAD = "download"
    UNKNOWN = "unknown"

class Verdict(str, Enum):
    GOOD = "GOOD"
    CONTROLLED = "CONTROLLED"
    PUA = "PUA"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"

class FactorCategory(str, Enum):
    STATIC = "static"
    ORIGIN = "origin"
    BEHAVIOR = "behavior"
    PERSISTENCE = "persistence"
    LOLBIN = "lolbin"
    MACRO = "macro"
    SCRIPT = "script"
    RELATIONAL = "relational"
    TEMPORAL = "temporal"
    REPUTATION = "reputation"
    SANDBOX = "sandbox"
    NEUTRAL = "neutral"

@dataclass
class Factor:
    name: str
    category: FactorCategory
    weight: float
    description: str = ""

class GraphContext(TypedDict, total=False):
    """Structured graph enrichment context stored on ArtifactObservation.graph_context."""
    session_id: str
    row_id: str
    hotspots: List[Dict[str, Any]]
    mapping_stats: Dict[str, Any]
    mapping_semantics_score: float
    domain_diversity_score: float
    confidence_breakdown: Dict[str, Any]
    key_factors: List[str]
    verdict: str | None
    confidence: float | None
    domains_present: List[str]
    narrative: str | None
    source: str | None


@dataclass
class ArtifactObservation:
    artifact_id: str
    sha256: str | None
    artifact_type: ArtifactType
    host: str | None
    path: str | None
    name: str
    size: int | None = None
    first_seen: float = field(default_factory=lambda: time.time())
    last_seen: float = field(default_factory=lambda: time.time())
    raw: dict[str, Any] = field(default_factory=dict)
    factors: list[str] = field(default_factory=list)
    factor_details: dict[str, dict[str, Any]] = field(default_factory=dict)
    embedding: list[float] | None = None
    cluster_id: str | None = None
    cluster_stats: dict[str, Any] | None = None
    graph_context: GraphContext | None = None
    reputation: dict[str, Any] | None = None
    risk_components: list[dict[str, Any]] = field(default_factory=list)
    base_risk: float = 0.0
    final_risk: float = 0.0
    verdict: Verdict = Verdict.UNKNOWN
    mitre: list[str] = field(default_factory=list)
    narrative: str | None = None
    overrides_applied: bool = False
    # Newly added enriched fields
    rarity: str | None = None            # RARE | EMERGING | COMMON
    host_count: int | None = None        # distinct hosts recently observed (heuristic)
    factor_contributions: list[dict[str,Any]] = field(default_factory=list)  # detailed per-factor deltas
    # Confidence / ambiguity (heuristic) added for analyst triage transparency
    risk_confidence: float | None = None   # 0..1 higher => more certain
    ambiguity: float | None = None         # 0..1 higher => more ambiguous

VERDICT_THRESHOLDS = {
    "GOOD": 0.20,
    "CONTROLLED": 0.35,
    "PUA": 0.55,
    "SUSPICIOUS": 0.75
}

def map_risk_to_verdict(r: float) -> Verdict:
    if r < VERDICT_THRESHOLDS["GOOD"]:
        return Verdict.GOOD
    if r < VERDICT_THRESHOLDS["CONTROLLED"]:
        return Verdict.CONTROLLED
    if r < VERDICT_THRESHOLDS["PUA"]:
        return Verdict.PUA
    if r < VERDICT_THRESHOLDS["SUSPICIOUS"]:
        return Verdict.SUSPICIOUS
    return Verdict.MALICIOUS

def stable_artifact_id(host: str, path: str|None, sha256: str|None, artifact_type: ArtifactType) -> str:
    base = f"{host}|{path}|{sha256}|{artifact_type}"
    return hashlib.sha256(base.encode()).hexdigest()[:20]
