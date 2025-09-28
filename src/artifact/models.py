from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional
import time, hashlib

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

@dataclass
class ArtifactObservation:
    artifact_id: str
    sha256: Optional[str]
    artifact_type: ArtifactType
    host: Optional[str]
    path: Optional[str]
    name: str
    size: Optional[int] = None
    first_seen: float = field(default_factory=lambda: time.time())
    last_seen: float = field(default_factory=lambda: time.time())
    raw: Dict[str, Any] = field(default_factory=dict)
    factors: List[str] = field(default_factory=list)
    factor_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    embedding: Optional[List[float]] = None
    cluster_id: Optional[str] = None
    cluster_stats: Optional[Dict[str, Any]] = None
    graph_context: Optional[Dict[str, Any]] = None
    reputation: Optional[Dict[str, Any]] = None
    risk_components: List[Dict[str, Any]] = field(default_factory=list)
    base_risk: float = 0.0
    final_risk: float = 0.0
    verdict: Verdict = Verdict.UNKNOWN
    mitre: List[str] = field(default_factory=list)
    narrative: Optional[str] = None
    overrides_applied: bool = False
    # Newly added enriched fields
    rarity: Optional[str] = None            # RARE | EMERGING | COMMON
    host_count: Optional[int] = None        # distinct hosts recently observed (heuristic)
    factor_contributions: List[Dict[str,Any]] = field(default_factory=list)  # detailed per-factor deltas
    # Confidence / ambiguity (heuristic) added for analyst triage transparency
    risk_confidence: Optional[float] = None   # 0..1 higher => more certain
    ambiguity: Optional[float] = None         # 0..1 higher => more ambiguous

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
