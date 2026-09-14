# Copied from JanuSec src/artifact/models.py (trimmed)
from __future__ import annotations
import hashlib, time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class ArtifactType(str, Enum):
    EXECUTABLE="executable"; SCRIPT="script"; DOCUMENT="document"; DRIVER="driver"; UNKNOWN="unknown"
class Verdict(str, Enum):
    GOOD="GOOD"; CONTROLLED="CONTROLLED"; PUA="PUA"; SUSPICIOUS="SUSPICIOUS"; MALICIOUS="MALICIOUS"; UNKNOWN="UNKNOWN"
class FactorCategory(str, Enum):
    STATIC="static"; ORIGIN="origin"; BEHAVIOR="behavior"; PERSISTENCE="persistence"; LOLBIN="lolbin"; MACRO="macro"; SCRIPT="script"; RELATIONAL="relational"; TEMPORAL="temporal"; REPUTATION="reputation"; SANDBOX="sandbox"; NEUTRAL="neutral"

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
    graph_context: dict[str, Any] | None = None
    reputation: dict[str, Any] | None = None
    risk_components: list[dict[str, Any]] = field(default_factory=list)
    base_risk: float = 0.0
    final_risk: float = 0.0
    verdict: Verdict = Verdict.UNKNOWN
    mitre: list[str] = field(default_factory=list)
    narrative: str | None = None
    overrides_applied: bool = False
    rarity: str | None = None
    host_count: int | None = None
    factor_contributions: list[dict[str,Any]] = field(default_factory=list)
    risk_confidence: float | None = None
    ambiguity: float | None = None

VERDICT_THRESHOLDS = {"GOOD":0.20,"CONTROLLED":0.35,"PUA":0.55,"SUSPICIOUS":0.75}

def map_risk_to_verdict(r: float) -> Verdict:
    if r < VERDICT_THRESHOLDS['GOOD']: return Verdict.GOOD
    if r < VERDICT_THRESHOLDS['CONTROLLED']: return Verdict.CONTROLLED
    if r < VERDICT_THRESHOLDS['PUA']: return Verdict.PUA
    if r < VERDICT_THRESHOLDS['SUSPICIOUS']: return Verdict.SUSPICIOUS
    return Verdict.MALICIOUS

def stable_artifact_id(host: str, path: str|None, sha256: str|None, artifact_type: ArtifactType) -> str:
    return hashlib.sha256(f"{host}|{path}|{sha256}|{artifact_type}".encode()).hexdigest()[:20]
