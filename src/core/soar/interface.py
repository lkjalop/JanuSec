"""SOAR Interface Skeleton

Defines abstraction for future integration with external XDR/SOAR platforms.
Phase 1: No-op / logging implementations to demonstrate extension points.
"""
from __future__ import annotations
from typing import Protocol, Any, Dict, Optional
import logging

logger = logging.getLogger(__name__)

class SOARClient(Protocol):
    async def create_alert(self, title: str, severity: str, details: Dict[str, Any]) -> Dict[str, Any]: ...
    async def enrich_case(self, case_id: str, enrichment: Dict[str, Any]) -> Dict[str, Any]: ...
    async def execute_action(self, action: str, target: str, params: Dict[str, Any]) -> Dict[str, Any]: ...

class NoOpSOARClient:
    async def create_alert(self, title: str, severity: str, details: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"[SOAR:NOOP] create_alert title={title} severity={severity}")
        return {"status":"noop","title":title}
    async def enrich_case(self, case_id: str, enrichment: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"[SOAR:NOOP] enrich_case case_id={case_id}")
        return {"status":"noop","case_id":case_id}
    async def execute_action(self, action: str, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"[SOAR:NOOP] execute_action action={action} target={target}")
        return {"status":"noop","action":action}

_soar_client: Optional[SOARClient] = None

def get_soar_client() -> SOARClient:
    global _soar_client
    if _soar_client is None:
        # Future: detect env vars for real Eclipse adapter & instantiate
        _soar_client = NoOpSOARClient()
    return _soar_client

__all__ = ["get_soar_client","SOARClient"]
