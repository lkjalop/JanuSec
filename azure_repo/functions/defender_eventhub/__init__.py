"""azure_repo.functions.defender_eventhub - small runtime shim copied from repo."""
from .mapper import normalize_defender_event, build_posture_payload

__all__ = ["normalize_defender_event", "build_posture_payload"]
