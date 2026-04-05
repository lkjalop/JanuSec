"""
Dashboard API Endpoints for JanuSec Platform Frontend
Provides real-time metrics, status updates, and dashboard data
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, Request

from .dependencies import get_platform_state
from .state import PlatformState
from core.threat_modeling.factor_taxonomy import FACTOR_MAESTRO, FACTOR_STRIDE
from .tenant_helpers import resolve_tenant_id

try:
    from core.finops.finops_manager import get_finops_manager
except ImportError:
    # Fallback if finops manager not available
    def get_finops_manager():
        return None

router = APIRouter()


@router.get('/api/v1/dashboard/status')
async def dashboard_status(
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    request: Request = None,
    state: PlatformState = Depends(get_platform_state)
) -> dict[str, Any]:
    """Get real-time dashboard status including XDR connection and alert counts"""

    # Get recent alerts for counts
    tenant_id = resolve_tenant_id(request, tenant_id)
    recent_alerts = state.recent_alerts(limit=100, tenant_id=tenant_id)

    # Count alerts by severity
    critical_count = len([a for a in recent_alerts if a.verdict == 'malicious' and a.score >= 0.9])
    high_count = len([a for a in recent_alerts if a.verdict == 'malicious' and 0.7 <= a.score < 0.9])
    medium_count = len([a for a in recent_alerts if a.verdict == 'suspicious' and 0.5 <= a.score < 0.7])

    # Simulate XDR connection status (in production, this would check actual connection)
    xdr_connected = time.time() % 10 < 8  # Simulate occasional disconnection

    return {
        'xdr_connection': {
            'status': 'connected' if xdr_connected else 'disconnected',
            'last_sync': time.time() - 120  # 2 minutes ago
        },
        'alerts': {
            'critical': critical_count,
            'high': high_count,
            'medium': medium_count,
            'total': len(recent_alerts)
        },
        'last_update': 'Just now',
        'last_update_timestamp': time.time(),
        'tenant_id': tenant_id
    }


@router.get('/api/v1/dashboard/metrics')
async def dashboard_metrics(
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    request: Request = None,
    state: PlatformState = Depends(get_platform_state)
) -> dict[str, Any]:
    """Get comprehensive dashboard metrics for metric cards"""

    # Get aggregated metrics
    agg_metrics = state.aggregate_metrics()

    # Get recent alerts for threat analysis
    tenant_id = resolve_tenant_id(request, tenant_id)
    recent_alerts = state.recent_alerts(limit=1000, tenant_id=tenant_id)

    # Calculate critical threats (high-confidence malicious alerts)
    critical_threats = len([a for a in recent_alerts if a.verdict == 'malicious' and a.score >= 0.8])

    # Get total artifacts processed (from decisions)
    decisions = agg_metrics.get('decisions', {})
    artifacts_analyzed = sum(decisions.values()) if decisions else 342

    # Calculate detection rate
    total_processed = artifacts_analyzed
    detected_threats = len([a for a in recent_alerts if a.verdict in ['malicious', 'suspicious']])
    detection_rate = (detected_threats / total_processed * 100) if total_processed > 0 else 98.2

    # Get average response time from heavy ops
    heavy_ops = agg_metrics.get('heavy_ops', {})
    avg_response_time = heavy_ops.get('avg_duration', 1.2) if heavy_ops else 1.2

    # Simple consolidation metric: raw vs. unique by id
    pre_count = len(recent_alerts)
    uniq_ids: set[str] = set(a.id for a in recent_alerts if a.id)
    post_count = len(uniq_ids) if uniq_ids else pre_count
    consolidation = {
        'pre': pre_count,
        'post': post_count,
        'factor': round((pre_count / post_count), 2) if post_count else 1.0,
    }

    return {
        'critical_threats': critical_threats,
        'artifacts_analyzed': artifacts_analyzed,
        'detection_rate': round(detection_rate, 1),
        'avg_response_time': f"{avg_response_time:.1f}s",
        'dedupe_consolidation': consolidation,
        'timestamp': time.time(),
        'tenant_id': tenant_id
    }


@router.get('/api/v1/dashboard/investigation/active')
async def active_investigation(
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    state: PlatformState = Depends(get_platform_state)
) -> dict[str, Any]:
    """Get active investigation details for the investigation console"""

    # Get the most recent critical alert as active investigation
    recent_alerts = state.recent_alerts(limit=50, tenant_id=tenant_id)
    critical_alerts = [a for a in recent_alerts if a.verdict == 'malicious' and a.score >= 0.8]

    if not critical_alerts:
        # Default investigation if no critical alerts
        return {
            'investigation_id': 'demo-001',
            'target': 'powerscan.exe',
            'sha256': 'a7c24b7dc90e8a67f9c3b1d4e5f6789abcdef123456789',
            'first_seen': '2025-09-23T14:32:00Z',
            'affected_hosts': ['DESKTOP-A1B2C3', 'LAPTOP-X4Y5Z6'],
            'mitre_techniques': ['T1059', 'T1105', 'T1057'],
            'status': 'active',
            'severity': 'critical',
            'confidence': 0.95,
            'evidence_count': 3
        }

    # Use most recent critical alert
    alert = critical_alerts[0]

    return {
        'investigation_id': f"inv-{alert.id or 'unknown'}",
        'target': alert.process_name or alert.filename or 'Unknown Process',
        'sha256': alert.hash or 'a7c24b7dc90e8a67f9c3b1d4e5f6789abcdef123456789',
        'first_seen': alert.ts,
        'affected_hosts': [alert.host] if alert.host else ['DESKTOP-HOST01'],
        'mitre_techniques': ['T1059', 'T1105', 'T1057'],  # Default MITRE techniques
        'status': 'active',
        'severity': 'critical' if alert.score >= 0.8 else 'high',
        'confidence': alert.score,
        'evidence_count': 3,
        'tenant_id': tenant_id
    }


@router.get('/api/v1/dashboard/integrations/status')
async def integration_status(
    tenant_id: str | None = Header(None, alias='X-Tenant-ID')
) -> dict[str, Any]:
    """Get status of all platform integrations"""

    return {
        'xdr': {
            'connected': True,
            'last_sync': time.time() - 120,  # 2 minutes ago
            'status': 'healthy',
            'endpoint': 'https://xdr.company.com/api'
        },
        'zeek': {
            'connected': False,
            'last_sync': None,
            'status': 'disconnected',
            'error': 'Connection timeout',
            'endpoint': 'https://zeek-sensor.local/api'
        },
        'slack': {
            'connected': False,
            'webhook_configured': False,
            'webhook_url': None,
            'status': 'not_configured'
        },
        'teams': {
            'connected': False,
            'webhook_configured': False,
            'webhook_url': None,
            'status': 'not_configured'
        },
        'tenant_id': tenant_id,
        'last_check': time.time()
    }


@router.post('/api/v1/dashboard/integrations/{service}/toggle')
async def toggle_integration(
    service: str,
    enabled: bool,
    tenant_id: str | None = Header(None, alias='X-Tenant-ID')
) -> dict[str, Any]:
    """Toggle integration service on/off"""

    valid_services = ['xdr', 'zeek', 'slack', 'teams']
    if service not in valid_services:
        return {'error': f'Invalid service. Must be one of: {valid_services}'}

    # In production, this would update actual integration settings
    return {
        'service': service,
        'enabled': enabled,
        'tenant_id': tenant_id,
        'message': f'{service.upper()} integration {"enabled" if enabled else "disabled"}',
        'timestamp': time.time()
    }


@router.get('/api/v1/dashboard/mitre/techniques/{investigation_id}')
async def mitre_mapping(
    investigation_id: str,
    tenant_id: str | None = Header(None, alias='X-Tenant-ID')
) -> dict[str, Any]:
    """Get MITRE ATT&CK technique mapping for an investigation"""

    # Default MITRE techniques for the investigation
    techniques = [
        {
            'id': 'T1059',
            'name': 'Command and Scripting Interpreter',
            'tactic': 'Execution',
            'confidence': 0.95,
            'description': 'PowerShell command execution detected'
        },
        {
            'id': 'T1105',
            'name': 'Ingress Tool Transfer',
            'tactic': 'Command and Control',
            'confidence': 0.87,
            'description': 'Remote file download activity'
        },
        {
            'id': 'T1057',
            'name': 'Process Discovery',
            'tactic': 'Discovery',
            'confidence': 0.73,
            'description': 'System process enumeration'
        }
    ]

    return {
        'investigation_id': investigation_id,
        'techniques': techniques,
        'total_techniques': len(techniques),
        'high_confidence': len([t for t in techniques if t['confidence'] > 0.8]),
        'tenant_id': tenant_id
    }


__all__ = ['router']

# ---------------- MAESTRO Maturity Dashboard ----------------

@router.get('/api/v1/dashboard/maturity')
async def maturity_dashboard() -> dict[str, Any]:
    """Return a simple MAESTRO maturity dashboard based on current taxonomy coverage.

    This is a static reflection of coverage (which factors map to which phases)
    and serves as a starting point for a richer maturity model.
    """
    phases: dict[str, int] = {}
    for f, plist in FACTOR_MAESTRO.items():
        for p in plist:
            phases[p] = phases.get(p, 0) + 1
    stride_counts: dict[str, int] = {}
    for f, cats in FACTOR_STRIDE.items():
        for c in cats:
            stride_counts[c] = stride_counts.get(c, 0) + 1
    return {
        'maestro_phase_coverage': sorted(phases.items(), key=lambda x: (-x[1], x[0])),
        'stride_category_coverage': sorted(stride_counts.items(), key=lambda x: (-x[1], x[0])),
        'notes': 'Counts represent how many factors currently map to each phase/category.'
    }
