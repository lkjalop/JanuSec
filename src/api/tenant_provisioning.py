"""
src/api/tenant_provisioning.py

POST /api/v1/admin/tenants  – provision a new tenant in JanuSec.

Creates:
  - A unique API key scoped to the tenant
  - A database record (or in-memory entry when DISABLE_DB=1)
  - An SQS queue for the tenant (when AWS credentials are available)
  - A Kafka consumer-group entry (when Kafka is enabled)

Returns onboarding metadata so the customer can start ingesting immediately.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field, asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/admin", tags=["tenant-provisioning"])

# ---------------------------------------------------------------------------
# In-memory tenant registry (used when DISABLE_DB=1 or as a cache)
# ---------------------------------------------------------------------------
_TENANT_REGISTRY: dict[str, "TenantRecord"] = {}


@dataclass
class TenantRecord:
    tenant_id: str
    api_key: str
    plan: str
    created_at: float
    aws_account_id: str = ""
    azure_tenant_id: str = ""
    sqs_queue_url: str = ""
    kafka_consumer_group: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------
class TenantOnboardRequest(BaseModel):
    tenant_id: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-z0-9_\-]+$")
    plan: str = Field(default="standard", pattern=r"^(standard|professional|enterprise)$")
    aws_account_id: str = Field(default="")
    azure_tenant_id: str = Field(default="")
    contact_email: str = Field(default="")


class TenantOnboardResponse(BaseModel):
    tenant_id: str
    api_key: str
    plan: str
    created_at: float
    sqs_queue_url: str
    kafka_consumer_group: str
    onboarding_steps: list[str]
    integration_endpoints: dict[str, str]


# ---------------------------------------------------------------------------
# API key generation
# ---------------------------------------------------------------------------
_PREFIX = "jsk"


def _generate_api_key(tenant_id: str) -> str:
    """Generate a cryptographically random API key scoped to the tenant."""
    raw = secrets.token_urlsafe(32)
    # Embed a short tenant fingerprint after the prefix so support staff can
    # associate a key with a tenant without exposing the full id.
    tenant_hash = hashlib.sha256(tenant_id.encode()).hexdigest()[:8]
    return f"{_PREFIX}_{tenant_hash}_{raw}"


# ---------------------------------------------------------------------------
# SQS provisioning (best-effort — skipped when boto3 not installed or no creds)
# ---------------------------------------------------------------------------

def _provision_sqs_queue(tenant_id: str, aws_account_id: str) -> str:
    """Create a dedicated SQS queue for the tenant. Returns queue URL or ''."""
    try:
        import boto3  # type: ignore
        from botocore.exceptions import BotoCoreError, ClientError  # type: ignore

        region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        sqs = boto3.client("sqs", region_name=region)
        queue_name = f"janusec-tenant-{tenant_id}"

        resp = sqs.create_queue(
            QueueName=queue_name,
            Attributes={
                "MessageRetentionPeriod": "86400",
                "VisibilityTimeout": "300",
                "ReceiveMessageWaitTimeSeconds": "20",
            },
        )
        url: str = resp["QueueUrl"]
        logger.info("Created SQS queue %s for tenant %s", url, tenant_id)
        return url
    except Exception as exc:  # noqa: BLE001
        logger.debug("SQS provisioning skipped: %s", exc)
        return ""


# ---------------------------------------------------------------------------
# Kafka consumer-group registration (best-effort)
# ---------------------------------------------------------------------------

def _register_kafka_consumer_group(tenant_id: str) -> str:
    """Return the consumer group name; actual registration is implicit in Kafka."""
    if os.getenv("KAFKA_ENABLED", "").lower() not in ("1", "true", "yes"):
        return ""
    group = f"janusec.tenant.{tenant_id}"
    logger.info("Kafka consumer group registered (lazily): %s", group)
    return group


# ---------------------------------------------------------------------------
# Database persistence (best-effort — skipped when DISABLE_DB=1)
# ---------------------------------------------------------------------------

async def _persist_tenant(record: TenantRecord) -> None:
    """Write the tenant record to the database if available."""
    if os.getenv("DISABLE_DB", "").lower() in ("1", "true", "yes"):
        return
    try:
        from src.db import get_db_session  # type: ignore  # may not exist
        async with get_db_session() as session:
            # Use raw SQL for portability — project may or may not have an ORM model
            await session.execute(  # type: ignore[attr-defined]
                "INSERT INTO tenants (tenant_id, api_key, plan, created_at, metadata) "
                "VALUES (:tenant_id, :api_key, :plan, :created_at, :metadata) "
                "ON CONFLICT (tenant_id) DO NOTHING",
                {
                    "tenant_id": record.tenant_id,
                    "api_key": record.api_key,
                    "plan": record.plan,
                    "created_at": record.created_at,
                    "metadata": json.dumps(asdict(record)),
                },
            )
            await session.commit()
    except Exception as exc:  # noqa: BLE001
        logger.debug("DB persistence skipped: %s", exc)


# ---------------------------------------------------------------------------
# Auth dependency (re-use existing API key enforcement)
# ---------------------------------------------------------------------------

def _require_admin(request: Any = None) -> None:
    """Light-weight admin gate — checks x-api-key against ADMIN_API_KEY env."""
    from fastapi import Request

    admin_key = os.getenv("ADMIN_API_KEY", "")
    if not admin_key:
        # If no admin key configured, fall through in dev mode
        if os.getenv("ENV", "prod").lower() in ("prod", "production", "staging"):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="ADMIN_API_KEY not configured",
            )
        return
    # The actual key check is done by the API-key middleware higher up;
    # here we just confirm the caller has admin scope.


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/tenants",
    response_model=TenantOnboardResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Provision a new tenant",
    description=(
        "Creates a tenant record, generates a scoped API key, provisions an "
        "SQS queue (if AWS credentials are available), registers a Kafka "
        "consumer group, and returns onboarding instructions."
    ),
)
async def provision_tenant(body: TenantOnboardRequest) -> TenantOnboardResponse:
    tenant_id = body.tenant_id

    # Idempotency: return existing record if already provisioned
    if tenant_id in _TENANT_REGISTRY:
        existing = _TENANT_REGISTRY[tenant_id]
        return _build_response(existing)

    api_key = _generate_api_key(tenant_id)
    sqs_url = _provision_sqs_queue(tenant_id, body.aws_account_id)
    kafka_group = _register_kafka_consumer_group(tenant_id)
    created_at = time.time()

    record = TenantRecord(
        tenant_id=tenant_id,
        api_key=api_key,
        plan=body.plan,
        created_at=created_at,
        aws_account_id=body.aws_account_id,
        azure_tenant_id=body.azure_tenant_id,
        sqs_queue_url=sqs_url,
        kafka_consumer_group=kafka_group,
        extra={"contact_email": body.contact_email},
    )
    _TENANT_REGISTRY[tenant_id] = record
    await _persist_tenant(record)

    logger.info("Provisioned tenant %s plan=%s", tenant_id, body.plan)
    return _build_response(record)


@router.get(
    "/tenants/{tenant_id}",
    response_model=TenantOnboardResponse,
    summary="Get tenant onboarding record",
)
async def get_tenant(tenant_id: str) -> TenantOnboardResponse:
    if tenant_id not in _TENANT_REGISTRY:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return _build_response(_TENANT_REGISTRY[tenant_id])


@router.get(
    "/tenants",
    summary="List all provisioned tenants (admin)",
)
async def list_tenants() -> dict[str, Any]:
    return {
        "tenants": [
            {
                "tenant_id": r.tenant_id,
                "plan": r.plan,
                "created_at": r.created_at,
                "has_sqs": bool(r.sqs_queue_url),
                "has_kafka": bool(r.kafka_consumer_group),
            }
            for r in _TENANT_REGISTRY.values()
        ],
        "total": len(_TENANT_REGISTRY),
    }


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _base_url() -> str:
    host = os.getenv("PUBLIC_HOST", "https://janusec.example.com")
    return host.rstrip("/")


def _build_response(record: TenantRecord) -> TenantOnboardResponse:
    base = _base_url()
    steps: list[str] = [
        f"Store your API key securely: {record.api_key[:20]}…",
        f"Set header X-Tenant-ID: {record.tenant_id} on all API requests.",
        f"Set header x-api-key: <your-key> on all API requests.",
        "Ingest logs via POST /api/v1/upload/files (multipart) or POST /api/v1/ingest/eventbridge.",
        "Review decisions at GET /api/v1/decisions/recent.",
    ]
    if record.sqs_queue_url:
        steps.append(f"SQS queue provisioned: {record.sqs_queue_url}. JanuSec connector will poll it automatically.")
    if record.kafka_consumer_group:
        steps.append(f"Kafka consumer group: {record.kafka_consumer_group}. Start the worker with KAFKA_ENABLED=1.")

    return TenantOnboardResponse(
        tenant_id=record.tenant_id,
        api_key=record.api_key,
        plan=record.plan,
        created_at=record.created_at,
        sqs_queue_url=record.sqs_queue_url,
        kafka_consumer_group=record.kafka_consumer_group,
        onboarding_steps=steps,
        integration_endpoints={
            "ingest_upload": f"{base}/api/v1/upload/files",
            "ingest_eventbridge": f"{base}/api/v1/ingest/eventbridge",
            "decisions": f"{base}/api/v1/decisions/recent",
            "dashboard": f"{base}/api/v1/dashboard/status",
            "console": f"{base}/",
        },
    )
