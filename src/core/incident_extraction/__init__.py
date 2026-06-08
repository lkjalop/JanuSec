"""Incident extraction module — splits correlation clusters into coherent incidents."""
from .incident_schema import CoherenceWarning, Incident
from .incident_splitter import extract_incidents
from .story_coherence import COHERENCE_THRESHOLD, CoherenceResult, compute_story_coherence

__all__ = [
    'extract_incidents',
    'Incident',
    'CoherenceWarning',
    'CoherenceResult',
    'compute_story_coherence',
    'COHERENCE_THRESHOLD',
]
