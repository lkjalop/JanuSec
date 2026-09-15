from fastapi import APIRouter, Depends, Request
from datetime import datetime
from src.core.detectors.missing_log_detector import TenantAwareMissingLogDetector
from src.api.tenant_helpers import resolve_tenant_id

router = APIRouter(prefix="/api/v1/missing-logs", tags=["missing-logs"])


@router.get("/{tenant_id}/status")
async def get_missing_logs_status(tenant_id: str, request: Request):
    tenant_id = resolve_tenant_id(request, tenant_id) or tenant_id
    detector = TenantAwareMissingLogDetector()
    missing = detector.check_missing_logs(tenant_id, datetime.utcnow())
    return {
        'tenant_id': tenant_id,
        'timestamp': datetime.utcnow().isoformat(),
        'missing_logs': missing,
        'total_missing': len(missing)
    }


@router.get("/{tenant_id}/root-cause/{connector_type}")
async def analyze_root_cause(tenant_id: str, connector_type: str, request: Request):
    tenant_id = resolve_tenant_id(request, tenant_id) or tenant_id
    detector = TenantAwareMissingLogDetector()
    root = detector.analyze_missing_log_root_cause(tenant_id, connector_type)
    return {
        'tenant_id': tenant_id,
        'connector_type': connector_type,
        'root_cause': root,
        'timestamp': datetime.utcnow().isoformat()
    }
