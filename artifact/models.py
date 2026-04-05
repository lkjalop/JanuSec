from dataclasses import dataclass
from enum import Enum
from typing import Optional

class ArtifactType(Enum):
    EXECUTABLE = 'executable'
    SCRIPT = 'script'
    OTHER = 'other'

@dataclass
class ArtifactObservation:
    artifact_id: str
    sha256: Optional[str]
    artifact_type: ArtifactType
    host: Optional[str]
    path: Optional[str]
    name: Optional[str]
    base_risk: float = 0.0
    final_risk: float = 0.0

__all__ = ['ArtifactObservation', 'ArtifactType']
