# Janusec MVP Action Plan — AWS + Azure + Network + Endpoint
**Direction**: Self-hosted, false-positive-first, T1 deterministic, T2 async, on-demand evidence gating
**Target**: Go-live in 3–4 weeks
**Date**: 2026-03-27

---

## Quick Reference: Honest Gap List

| Gap | Severity | Current State | Fix Effort |
|-----|----------|---------------|------------|
| `correlation_emission` never generated in pipeline | 🔴 CRITICAL | T1 has dead input | 0.5d |
| AWS connectors CLI-only, not HTTP-triggered | 🔴 CRITICAL | Manual run only | 1d |
| Azure Event Hub consumer — doesn't exist | 🔴 CRITICAL | IAM stub only | 2d |
| Sysmon endpoint ingest path — unclear wiring | 🔴 CRITICAL | Parser only | 0.5d |
| Persona report — no LLM integration visible | 🟠 HIGH | Template stub | 1d |
| Evidence acquisition — no API endpoint | 🟠 HIGH | Data model only | 1d |
| Feedback → decision re-scoring chain broken | 🟠 HIGH | Weights updated, no rescore | 1d |
| T2 triggering — only wired to CSV, not pipeline decisions | 🟠 HIGH | Separate endpoint | 0.5d |
| Docker Compose — no Ollama service defined | 🟡 MEDIUM | Must add | 0.5d |
| GCP connectors — scaffold level | 🟢 LOW | Defer to sprint 2 | — |

---

## Architecture: What the MVP Must Do

```
TELEMETRY IN
   AWS (CloudTrail, GuardDuty, VPC Flow)          ← connectors/aws/ ✅ (needs HTTP wiring)
   Azure (Event Hub → Entra ID, Defender)          ← connectors/azure/ ❌ (must build)
   Network (Zeek conn/dns/http/ssl)                ← live/zeek_adapter.py ✅
   Endpoint (Sysmon EVTX / log_batch)              ← connectors/sysmon_evtx.py ⚠️

INGEST LAYER
   POST /api/v1/ingest/stream                      ← api/stream_ingest.py ✅
   POST /api/v1/endpoints/log_batch                ← needs Sysmon wiring ⚠️
   POST /api/v1/webhooks/* (HMAC)                  ← api/webhook_middleware.py ✅
   Scheduler: /api/v1/connectors/aws/poll          ← must add ❌
   Scheduler: /api/v1/connectors/azure/poll        ← must add ❌

PIPELINE (33 stages)
   24 FAST/CORE always                             ← stages/__init__.py ✅
   5 HEAVY gated by confidence < 0.8 or evidence  ← pipeline.py ✅
   correlation_emission generated after core       ← MISSING, must fix ❌

TRIAGE
   T1 deterministic: summarize_tier1(event)        ← tier1_summarizer.py ✅ (needs input fix)
   T2 async LLM: high-severity + ambiguous only    ← redis_tier2.py ✅ (needs pipeline trigger)
   FP reduction: factor suppression + feedback     ← factor_quality.py ⚠️ (wiring incomplete)

REPORTING
   Analyst / Manager / Forensics persona           ← persona_format.py ⚠️ (scaffold only)
   HTML / PDF / SSE decisions stream               ← report_endpoints.py ✅ (needs persona LLM)
   Executive dashboard                             ← executive_report_endpoints.py ✅

EVIDENCE GATING (on-demand, not automatic)
   POST /api/v1/evidence/recommend                 ← must create ❌
   "recommend KAPE / memory / pcap follow-up"
   Analyst approves, does NOT auto-execute

FEEDBACK LOOP
   POST /api/v1/feedback (mark legit/suspicious/malicious) ← routes/feedback.py ✅
   POST /api/v1/feedback/decision                  ← decision_feedback_endpoints.py ✅
   Weight update → factor re-scoring               ← adaptive_tuner.py ⚠️ (chain incomplete)

SELF-HOSTED
   docker-compose.yml (postgres + redis + app + worker) ← exists ✅
   + ollama service                                ← missing ❌
   DEFAULT_TENANT=default (single-tenant bypass)   ← env var ✅
```

---

## File-by-File Action Plan

### 🔴 CRITICAL — Pipeline Must Work End-to-End

---

#### FIX 1: Generate `correlation_emission` in Pipeline
**Problem**: `tier1_summarizer.py` requires `event['correlation_emission']` but no stage produces it.
**File**: `src/core/event_pipeline/pipeline.py`
**Where**: After the correlation stage runs (around line 280–320 in the stage loop)

```python
# AFTER correlation stage completes, synthesize correlation_emission
# Add this function to pipeline.py:

def _build_correlation_emission(event: dict, stage_results: list) -> dict:
    """
    Build the correlation_emission dict that T1 summarizer needs.
    Synthesizes from: factors accumulated during pipeline, hunt_lane hits,
    stage verdicts, MITRE mappings produced by mapping stage.
    """
    factors = event.get('factors', [])
    mitre = event.get('mitre_techniques', [])
    evidence = []

    # Collect evidence strings from stage outputs
    for sr in stage_results:
        if sr.get('evidence'):
            evidence.extend(sr['evidence'] if isinstance(sr['evidence'], list) else [sr['evidence']])

    # Pick the top correlation rule name
    rule = (
        event.get('matched_rule')
        or event.get('hunt_lane_hit')
        or (factors[0]['name'] if factors else 'pipeline_detection')
    )

    computed_score = max((f.get('score', 0) for f in factors), default=0.0)

    return {
        'rule': rule,
        'computed_score': computed_score,
        'mitre': sorted(set(mitre)),
        'evidence': sorted(set(evidence))[:10],  # cap at 10 evidence strings
    }
```

**In `process_event()`**, add after stage loop:
```python
# Around line 310 (after all stages run):
emission = _build_correlation_emission(event, accumulated_stage_results)
event['correlation_emission'] = emission

# Then call T1:
from src.core.correlation.tier1_summarizer import summarize_tier1
t1 = summarize_tier1(event)
result.t1_summary = t1
```

**Lines to touch**: `pipeline.py` — add `_build_correlation_emission()` function + call in `process_event()`
**Impact**: T1 summary starts working on every event.

---

#### FIX 2: Wire T2 from Pipeline Decision (not just CSV endpoint)
**Problem**: T2 is only triggered from `/api/v1/csv/tier2_summarize`, not from pipeline decisions.
**Files**:
- `src/core/event_pipeline/pipeline.py` — add T2 enqueue after T1
- `src/queue/redis_tier2.py` — already has `enqueue()` method

**Add to `process_event()` after T1 summary**:
```python
# Trigger T2 only for: high severity OR ambiguous (confidence 0.4-0.7) OR explicit request
should_t2 = (
    t1['score'] >= 0.8                    # high severity
    or 0.4 <= t1['score'] <= 0.7          # ambiguous zone
    or event.get('force_t2', False)       # manager/forensics explicit request
)

if should_t2:
    from src.queue.redis_tier2 import enqueue as t2_enqueue
    t2_enqueue({
        'event_id': event.get('id'),
        'tenant_id': tenant_id,
        't1_summary': t1,
        'event': event,
        'persona': event.get('report_persona', 'analyst'),
    })
```

**Lines to touch**: `pipeline.py` ~line 320, after T1 block.

---

#### FIX 3: Sysmon Endpoint Ingest — Clear HTTP Path
**Problem**: `sysmon_evtx.py` has the parser but no clear HTTP path for endpoint telemetry ingest.
**File**: `src/api/routes/events.py` (or `server.py`)

**Add/verify this endpoint exists**:
```python
# src/api/routes/events.py — add if missing

@router.post('/api/v1/endpoints/log_batch')
async def endpoint_log_batch(
    payload: EndpointLogBatch,
    _auth = Depends(alerts_auth),
):
    """
    Accept Sysmon EVTX, Windows Event Log, or pre-normalized endpoint events.
    Normalizes via sysmon_evtx.normalize_sysmon_event() then routes to pipeline.
    """
    from src.connectors.sysmon_evtx import normalize_sysmon_event
    results = []
    for raw_event in payload.events:
        normalized = normalize_sysmon_event(raw_event)
        normalized['source'] = 'endpoint'
        normalized['tenant_id'] = payload.tenant_id or DEFAULT_TENANT
        # Push into event queue / pipeline
        result = await pipeline.process_event(normalized)
        results.append({'event_id': normalized.get('id'), 'verdict': result.verdict})
    return {'processed': len(results), 'results': results}
```

**Lines to touch**: `src/api/routes/events.py` — add endpoint if not present, or verify `log_batch` route at line 3711 of server.py actually calls `normalize_sysmon_event`.

---

### 🔴 CRITICAL — Cloud Connectors (AWS HTTP + Azure Build)

---

#### FIX 4: AWS Connectors — Add HTTP Poll Endpoint
**Problem**: AWS connectors are CLI-only (`runner.py`). Need HTTP endpoint for scheduled polling.
**File**: Create `src/api/routes/connectors.py` (or add to existing connectors route)

```python
# src/api/routes/connectors.py

from src.connectors.aws.cloudtrail import CloudTrailConnector
from src.connectors.aws.guardduty import GuardDutyConnector
from src.connectors.aws.vpcflow import VPCFlowConnector
from src.connectors.aws.base import AWSConnectorConfig

@router.post('/api/v1/connectors/aws/poll')
async def poll_aws(
    source: Literal['cloudtrail', 'guardduty', 'vpcflow', 'securityhub'] = 'cloudtrail',
    since_hours: int = 1,
    _auth = Depends(alerts_auth),
    background_tasks: BackgroundTasks = None,
):
    """
    Trigger incremental fetch from AWS source.
    Runs in background, ingests events into pipeline.
    """
    background_tasks.add_task(_run_aws_poll, source, since_hours)
    return {'status': 'polling', 'source': source, 'since_hours': since_hours}


async def _run_aws_poll(source: str, since_hours: int):
    cfg = AWSConnectorConfig(
        role_arn=os.environ.get('AWS_ROLE_ARN'),
        region=os.environ.get('AWS_REGION', 'us-east-1'),
    )
    connector_map = {
        'cloudtrail': CloudTrailConnector,
        'guardduty': GuardDutyConnector,
        'vpcflow': VPCFlowConnector,
    }
    connector = connector_map[source](cfg)
    since = datetime.utcnow() - timedelta(hours=since_hours)
    count = 0
    async for event in connector.fetch_events(since):
        event['source'] = f'aws_{source}'
        event['tenant_id'] = DEFAULT_TENANT
        await pipeline.process_event(event)
        count += 1
    logger.info('aws_poll', source=source, events=count)
```

**Also add cron-style scheduler** (simple APScheduler or cron container):
```python
# src/api/scheduler.py — CREATE
# Polls AWS every N minutes based on env vars

AWS_POLL_INTERVAL_MINUTES = int(os.getenv('AWS_POLL_INTERVAL_MINUTES', '15'))

def start_aws_scheduler(app):
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    scheduler = AsyncIOScheduler()
    if os.getenv('AWS_CLOUDTRAIL_ENABLED', '0') == '1':
        scheduler.add_job(_run_aws_poll, 'interval', minutes=AWS_POLL_INTERVAL_MINUTES,
                          args=['cloudtrail', AWS_POLL_INTERVAL_MINUTES])
    if os.getenv('AWS_GUARDDUTY_ENABLED', '0') == '1':
        scheduler.add_job(_run_aws_poll, 'interval', minutes=AWS_POLL_INTERVAL_MINUTES,
                          args=['guardduty', AWS_POLL_INTERVAL_MINUTES])
    scheduler.start()
    return scheduler
```

**Files to create/edit**:
- CREATE `src/api/routes/connectors.py`
- CREATE `src/api/scheduler.py`
- EDIT `src/api/server.py` — register connectors router + start scheduler on startup

---

#### BUILD 5: Azure Event Hub Consumer — Full Build
**This is the biggest missing piece.**

**Files to create**:

```
src/connectors/azure/
├── __init__.py               CREATE (empty)
├── base.py                   CREATE
├── event_hub.py              CREATE — main consumer
├── entra_id.py               CREATE — sign-in + audit via Graph API
├── defender_cloud.py         CREATE — Defender for Cloud findings
└── normalizer.py             CREATE — Azure → canonical_envelope
```

**`src/connectors/azure/base.py`**:
```python
import os, json, logging
from datetime import datetime, timezone
from pathlib import Path

CHECKPOINT_DIR = os.getenv('AZURE_CHECKPOINT_DIR', 'data/checkpoints/azure')

class AzureConnectorBase:
    source_name: str = 'azure_base'

    def load_checkpoint(self) -> dict:
        p = Path(CHECKPOINT_DIR) / f'{self.source_name}.json'
        if p.exists():
            return json.loads(p.read_text())
        return {}

    def save_checkpoint(self, data: dict) -> None:
        p = Path(CHECKPOINT_DIR) / f'{self.source_name}.json'
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data))

    def canonical_envelope(self, raw: dict, event_type: str) -> dict:
        """Wrap Azure event into Janusec canonical format."""
        return {
            'source': f'azure_{event_type}',
            'raw': raw,
            'tenant_id': raw.get('tenantId') or os.getenv('DEFAULT_TENANT', 'default'),
            'recv_ts': datetime.now(timezone.utc).isoformat(),
            'id': raw.get('id') or raw.get('operationId') or raw.get('correlationId', ''),
            'actor': raw.get('callerIpAddress') or raw.get('initiatedBy', {}).get('user', {}).get('userPrincipalName', ''),
            'action': raw.get('operationName', {}).get('value', '') if isinstance(raw.get('operationName'), dict) else raw.get('operationName', ''),
        }
```

**`src/connectors/azure/event_hub.py`**:
```python
"""
Azure Event Hub consumer — AMQP-based, async, checkpoint-enabled.
Wires: Azure Monitor / Diagnostic Settings → Event Hub → Janusec pipeline.

Requires: pip install azure-eventhub>=5.11.0
Env vars:
  AZURE_EVENTHUB_CONNECTION_STRING   — Event Hub Shared Access Signature connection string
  AZURE_EVENTHUB_NAME                — e.g. "janusec-telemetry"
  AZURE_EVENTHUB_CONSUMER_GROUP      — default "$Default"
"""
import asyncio, os, logging
from datetime import datetime, timezone

try:
    from azure.eventhub.aio import EventHubConsumerClient
    from azure.eventhub import EventData
    HAS_EVENTHUB = True
except ImportError:
    HAS_EVENTHUB = False

from .base import AzureConnectorBase
from .normalizer import normalize_azure_event

logger = logging.getLogger(__name__)

class EventHubConnector(AzureConnectorBase):
    source_name = 'azure_event_hub'

    def __init__(self):
        self.connection_string = os.environ['AZURE_EVENTHUB_CONNECTION_STRING']
        self.eventhub_name = os.environ['AZURE_EVENTHUB_NAME']
        self.consumer_group = os.getenv('AZURE_EVENTHUB_CONSUMER_GROUP', '$Default')
        self._on_event_callback = None  # Set by caller

    def set_callback(self, callback):
        """callback(canonical_event: dict) -> None"""
        self._on_event_callback = callback

    async def consume(self):
        if not HAS_EVENTHUB:
            raise ImportError('azure-eventhub package not installed. pip install azure-eventhub>=5.11.0')

        client = EventHubConsumerClient.from_connection_string(
            self.connection_string,
            consumer_group=self.consumer_group,
            eventhub_name=self.eventhub_name,
        )
        async with client:
            await client.receive(
                on_event=self._handle_event,
                starting_position=self._get_checkpoint_position(),
            )

    async def _handle_event(self, partition_context, event: 'EventData'):
        try:
            import json
            body = json.loads(event.body_as_str())
            # Azure Event Hub records may be batched under 'records' key
            records = body.get('records', [body])
            for record in records:
                canonical = normalize_azure_event(record)
                canonical = {**self.canonical_envelope(record, 'event_hub'), **canonical}
                if self._on_event_callback:
                    await self._on_event_callback(canonical)
            # Save checkpoint per partition
            await partition_context.update_checkpoint(event)
        except Exception as e:
            logger.error('event_hub_handle_error', error=str(e))

    def _get_checkpoint_position(self):
        cp = self.load_checkpoint()
        return cp.get('last_sequence', '-1')
```

**`src/connectors/azure/entra_id.py`**:
```python
"""
Microsoft Entra ID (Azure AD) connector.
Fetches sign-in logs and audit logs via Microsoft Graph API.

Requires: pip install msal>=1.26 requests>=2.31
Env vars:
  AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
"""
import os, logging
from datetime import datetime, timedelta, timezone
from typing import Iterable

try:
    import msal, requests
    HAS_MSAL = True
except ImportError:
    HAS_MSAL = False

from .base import AzureConnectorBase
from .normalizer import normalize_entra_signin, normalize_entra_audit

logger = logging.getLogger(__name__)
GRAPH_BASE = 'https://graph.microsoft.com/v1.0'


class EntraIDConnector(AzureConnectorBase):
    source_name = 'azure_entra_id'

    def __init__(self):
        self.tenant_id = os.environ['AZURE_TENANT_ID']
        self.client_id = os.environ['AZURE_CLIENT_ID']
        self.client_secret = os.environ['AZURE_CLIENT_SECRET']
        self._token = None
        self._token_expires = datetime.min

    def _get_token(self) -> str:
        if not HAS_MSAL:
            raise ImportError('msal not installed. pip install msal>=1.26')
        if datetime.utcnow() < self._token_expires:
            return self._token
        app = msal.ConfidentialClientApplication(
            self.client_id,
            authority=f'https://login.microsoftonline.com/{self.tenant_id}',
            client_credential=self.client_secret,
        )
        result = app.acquire_token_for_client(scopes=['https://graph.microsoft.com/.default'])
        self._token = result['access_token']
        self._token_expires = datetime.utcnow() + timedelta(seconds=result['expires_in'] - 60)
        return self._token

    def _graph_get(self, path: str, params: dict = None) -> dict:
        headers = {'Authorization': f'Bearer {self._get_token()}', 'Content-Type': 'application/json'}
        r = requests.get(f'{GRAPH_BASE}{path}', headers=headers, params=params or {}, timeout=30)
        r.raise_for_status()
        return r.json()

    def fetch_signin_logs(self, since: datetime = None) -> Iterable[dict]:
        """Fetch sign-in logs since timestamp. Yields canonical events."""
        cp = self.load_checkpoint()
        last_ts = since or datetime.fromisoformat(cp.get('signin_last_ts', '')) if cp.get('signin_last_ts') else (datetime.utcnow() - timedelta(hours=1))
        filter_str = f"createdDateTime ge {last_ts.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        page = self._graph_get('/auditLogs/signIns', {'$filter': filter_str, '$top': 100})
        newest_ts = None
        while page:
            for record in page.get('value', []):
                newest_ts = record.get('createdDateTime')
                canonical = normalize_entra_signin(record)
                yield {**self.canonical_envelope(record, 'entra_signin'), **canonical}
            next_link = page.get('@odata.nextLink')
            if not next_link:
                break
            import requests as req
            page = req.get(next_link, headers={'Authorization': f'Bearer {self._get_token()}'}, timeout=30).json()
        if newest_ts:
            self.save_checkpoint({**cp, 'signin_last_ts': newest_ts})

    def fetch_audit_logs(self, since: datetime = None) -> Iterable[dict]:
        """Fetch directory audit logs (IAM changes, role assignments, etc.)"""
        cp = self.load_checkpoint()
        last_ts = since or datetime.fromisoformat(cp.get('audit_last_ts', '')) if cp.get('audit_last_ts') else (datetime.utcnow() - timedelta(hours=1))
        filter_str = f"activityDateTime ge {last_ts.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        page = self._graph_get('/auditLogs/directoryAudits', {'$filter': filter_str, '$top': 100})
        newest_ts = None
        while page:
            for record in page.get('value', []):
                newest_ts = record.get('activityDateTime')
                canonical = normalize_entra_audit(record)
                yield {**self.canonical_envelope(record, 'entra_audit'), **canonical}
            next_link = page.get('@odata.nextLink')
            if not next_link:
                break
            import requests as req
            page = req.get(next_link, headers={'Authorization': f'Bearer {self._get_token()}'}, timeout=30).json()
        if newest_ts:
            self.save_checkpoint({**cp, 'audit_last_ts': newest_ts})
```

**`src/connectors/azure/normalizer.py`**:
```python
"""
Normalize Azure event schemas to Janusec canonical_envelope fields.
Each function returns a partial dict merged with canonical_envelope() base.
"""
from typing import Optional


def normalize_azure_event(raw: dict) -> dict:
    """Generic Azure event normalization — route by category/operationName."""
    category = raw.get('category', '')
    if 'SignIn' in category or 'signin' in category.lower():
        return normalize_entra_signin(raw)
    if 'AuditLogs' in category or 'Audit' in category:
        return normalize_entra_audit(raw)
    if 'SecurityAlert' in category or 'Defender' in category:
        return normalize_defender_alert(raw)
    return _generic_normalize(raw)


def normalize_entra_signin(raw: dict) -> dict:
    """Microsoft Entra ID sign-in log → Janusec fields."""
    location = raw.get('location', {})
    return {
        'event_type': 'auth',
        'user': raw.get('userPrincipalName', ''),
        'user_id': raw.get('userId', ''),
        'src_ip': raw.get('ipAddress', ''),
        'app': raw.get('appDisplayName', ''),
        'client_app': raw.get('clientAppUsed', ''),
        'device_os': raw.get('deviceDetail', {}).get('operatingSystem', ''),
        'location_country': location.get('countryOrRegion', ''),
        'location_city': location.get('city', ''),
        'mfa_result': raw.get('authenticationRequirement', ''),
        'risk_level': raw.get('riskLevelAggregated', ''),
        'risk_state': raw.get('riskState', ''),
        'conditional_access': raw.get('conditionalAccessStatus', ''),
        'status_code': raw.get('status', {}).get('errorCode', 0),
        'success': raw.get('status', {}).get('errorCode', 1) == 0,
        'ts': raw.get('createdDateTime', ''),
        'mitre_hint': ['T1078', 'T1110'],  # valid accounts / brute force
    }


def normalize_entra_audit(raw: dict) -> dict:
    """Entra ID directory audit log → Janusec fields (IAM changes)."""
    initiator = raw.get('initiatedBy', {})
    user_initiator = initiator.get('user', {})
    return {
        'event_type': 'iam_change',
        'actor': user_initiator.get('userPrincipalName', '') or initiator.get('app', {}).get('displayName', ''),
        'actor_id': user_initiator.get('id', ''),
        'action': raw.get('activityDisplayName', ''),
        'result': raw.get('result', ''),
        'target': [t.get('displayName', '') for t in raw.get('targetResources', [])],
        'target_type': [t.get('type', '') for t in raw.get('targetResources', [])],
        'ts': raw.get('activityDateTime', ''),
        'mitre_hint': ['T1098', 'T1078'],  # account manipulation / valid accounts
    }


def normalize_defender_alert(raw: dict) -> dict:
    """Microsoft Defender for Cloud alert → Janusec fields."""
    return {
        'event_type': 'security_alert',
        'alert_type': raw.get('alertType', ''),
        'severity': raw.get('severity', 'unknown').lower(),
        'title': raw.get('alertDisplayName', ''),
        'description': raw.get('description', ''),
        'src_ip': raw.get('compromisedEntity', ''),
        'remediation': raw.get('remediationSteps', ''),
        'ts': raw.get('startTimeUtc', ''),
        'mitre_hint': raw.get('intent', '').split(',') if raw.get('intent') else [],
    }


def _generic_normalize(raw: dict) -> dict:
    return {
        'event_type': raw.get('category', 'unknown'),
        'action': str(raw.get('operationName', '')),
        'result': raw.get('resultType', ''),
        'ts': raw.get('time', ''),
    }
```

---

### 🟠 HIGH — FP Reduction Wiring

---

#### FIX 6: Wire Feedback → Factor Suppression → Re-score
**Problem**: Feedback endpoints accept votes but don't flow through to active suppression or re-score pending decisions.

**File**: `src/api/routes/feedback.py`

**Add after `apply_vote()` call**:
```python
# After apply_vote(factor, vote) call (around line 87):

from src.core.quality.factor_quality import get_factor_quality_manager
fqm = get_factor_quality_manager()

if label == 'false_positive':
    # Increment FP count for each factor in this decision
    for factor_name in factors:
        fqm.record_outcome(factor_name, is_tp=False)

elif label in ('true_positive', 'malicious'):
    for factor_name in factors:
        fqm.record_outcome(factor_name, is_tp=True)

# Persist updated suppression state
fqm.persist()

# Emit updated suppression thresholds (optional Prometheus gauge)
for factor_name in factors:
    precision = fqm.get_precision(factor_name)
    FACTOR_PRECISION_GAUGE.labels(factor=factor_name).set(precision)
```

**File**: `src/core/quality/factor_quality.py`

**Verify/add `record_outcome()` and `get_precision()` methods**:
```python
def record_outcome(self, factor_name: str, is_tp: bool) -> None:
    """Record a TP or FP outcome for a factor. Used by feedback loop."""
    state = self._state.setdefault(factor_name, {'tp': 0, 'fp': 0})
    if is_tp:
        state['tp'] += 1
    else:
        state['fp'] += 1

def get_precision(self, factor_name: str) -> float:
    """Return precision (TP rate) for factor. 1.0 if not enough data."""
    state = self._state.get(factor_name, {})
    tp = state.get('tp', 0)
    fp = state.get('fp', 0)
    total = tp + fp
    if total < self._min_observations:
        return 1.0  # benefit of the doubt
    return tp / total

def is_suppressed(self, factor_name: str) -> bool:
    """Return True if factor FP rate exceeds threshold."""
    precision = self.get_precision(factor_name)
    return precision < (1.0 - self._fp_threshold)
```

**File**: `src/core/event_pipeline/stages/advanced.py` (correlation stage)

**Use suppression in correlation stage**:
```python
# In correlation stage, before adding factor to emission:
from src.core.quality.factor_quality import get_factor_quality_manager
fqm = get_factor_quality_manager()

active_factors = [
    f for f in candidate_factors
    if not fqm.is_suppressed(f['name'])
]
```

---

### 🟠 HIGH — Persona Reports with LLM Integration

---

#### FIX 7: Persona Report LLM Integration
**Problem**: `persona_format.py` has templates but no LLM call. Reports are template-only HTML.

**File**: `src/analysis/persona_format.py`

**Add LLM generation function**:
```python
# Add to persona_format.py

async def generate_persona_report(
    t1_summary: dict,
    t2_summary: dict,
    persona: str,  # 'analyst' | 'manager' | 'forensics'
    event: dict,
) -> str:
    """
    Generate LLM-enriched persona report text.
    Falls back to template-only if LLM unavailable.
    """
    from src.integrations.llm_client import get_default_client
    from src.ai.tier2_prompts import build_persona_prompt

    template = PERSONA_TEMPLATES.get(persona, PERSONA_TEMPLATES['analyst'])
    context = {
        't1': t1_summary,
        't2': t2_summary,
        'event_type': event.get('event_type', ''),
        'source': event.get('source', ''),
        'mitre': t1_summary.get('mitre', []),
        'score': t1_summary.get('score', 0),
        'top_factors': t1_summary.get('top_factors', []),
    }

    prompt = f"{template}\n\nContext:\n{json.dumps(context, indent=2)}\n\nGenerate the report:"

    client = get_default_client()
    try:
        response = await client.generate(prompt, max_tokens=500)
        return response.strip()
    except Exception:
        # Fallback: deterministic template fill
        return _fallback_persona_text(persona, t1_summary)


def _fallback_persona_text(persona: str, t1: dict) -> str:
    score = t1.get('score', 0)
    severity = 'Critical' if score >= 0.85 else 'High' if score >= 0.65 else 'Medium' if score >= 0.4 else 'Low'
    mitre = ', '.join(t1.get('mitre', [])[:3]) or 'Unknown'
    reasons = '; '.join(t1.get('reason', [])[:3]) or 'No evidence collected'

    if persona == 'manager':
        return f"[{severity}] {t1.get('title', 'Detection')} — Score: {score:.0%}. MITRE: {mitre}. Recommend immediate investigation."
    elif persona == 'forensics':
        return (
            f"Investigation checklist for: {t1.get('title', 'Detection')}\n"
            f"1. Isolate affected host\n"
            f"2. Collect process list and network connections\n"
            f"3. Evidence: {reasons}\n"
            f"4. MITRE techniques: {mitre}\n"
            f"5. Recommended: memory dump + PCAP review"
        )
    else:  # analyst
        return f"{t1.get('title', 'Detection')} detected (score: {score:.0%}). Evidence: {reasons}. MITRE: {mitre}."
```

**File**: `src/api/report_endpoints.py`

**Wire persona into report generation** (around line 23):
```python
@router.post('/api/v1/report/generate')
async def generate_report(payload: ReportRequest):
    persona = payload.persona or 'analyst'

    # Get T1 from decision record
    t1 = await decisions_repo.get_t1_summary(payload.event_id)
    # Get T2 if available
    t2 = await tier2_repo.get_result(payload.event_id) or {}

    # Generate persona text (LLM or fallback)
    persona_text = await generate_persona_report(t1, t2, persona, payload.event or {})

    html = build_report_html({
        'title': t1.get('title', 'Security Alert'),
        'persona': persona,
        'persona_text': persona_text,
        't1': t1,
        't2': t2,
        'mitre': t1.get('mitre', []),
        'score': t1.get('score', 0),
    })
    return HTMLResponse(content=html)
```

---

### 🟠 HIGH — On-Demand Evidence Gating

---

#### CREATE 8: Evidence Recommendation API (NOT Auto-Execute)
**File**: CREATE `src/api/routes/evidence.py`

```python
"""
On-demand evidence gating.
Pipeline can RECOMMEND evidence collection; analyst must APPROVE before collection occurs.
Does NOT auto-execute KAPE or memory dumps.
"""
from fastapi import APIRouter, Depends
from src.api.auth_rate_limit import alerts_auth
from src.artifact.memory_acquisition import AcquisitionPlan

router = APIRouter(prefix='/api/v1/evidence', tags=['evidence'])


@router.post('/recommend')
async def recommend_evidence(
    event_id: str,
    host: str,
    os_family: str = 'windows',
    reason: str = '',
    triggered_by: list[str] = None,  # which pipeline factors triggered this
    _auth = Depends(alerts_auth),
):
    """
    Recommend evidence collection for a host. Stores recommendation.
    Does NOT execute. Analyst must call /approve to trigger.
    """
    plan = AcquisitionPlan(
        attestation_id=f'rec_{event_id}',
        host=host,
        os_family=os_family,
        case_id=event_id,
        tenant_id=DEFAULT_TENANT,
        status='recommended',
        alerts=[reason] if reason else [],
    )
    # Store recommendation (file-based or DB)
    _store_recommendation(plan)
    return {
        'recommendation_id': plan.attestation_id,
        'host': host,
        'status': 'recommended',
        'triggered_by': triggered_by or [],
        'next_step': f'POST /api/v1/evidence/{plan.attestation_id}/approve to execute',
    }


@router.post('/{recommendation_id}/approve')
async def approve_evidence(
    recommendation_id: str,
    approved_by: str,
    _auth = Depends(alerts_auth),
):
    """Analyst approves evidence collection. Updates status to 'approved'."""
    plan = _load_recommendation(recommendation_id)
    if not plan:
        raise HTTPException(404, 'recommendation not found')
    plan.status = 'approved'
    plan.approved_by = approved_by
    _store_recommendation(plan)
    return {'status': 'approved', 'recommendation_id': recommendation_id,
            'message': 'Evidence collection approved. Execute via your KAPE/memory acquisition tooling.'}


@router.get('/')
async def list_recommendations(status: str = None, _auth = Depends(alerts_auth)):
    """List all evidence recommendations, optionally filtered by status."""
    recs = _load_all_recommendations()
    if status:
        recs = [r for r in recs if r.get('status') == status]
    return {'recommendations': recs, 'total': len(recs)}


def _store_recommendation(plan):
    import json
    from pathlib import Path
    p = Path('data/evidence_recommendations') / f'{plan.attestation_id}.json'
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(plan.__dict__, default=str))


def _load_recommendation(rec_id: str):
    import json
    from pathlib import Path
    p = Path('data/evidence_recommendations') / f'{rec_id}.json'
    if p.exists():
        return json.loads(p.read_text())
    return None


def _load_all_recommendations():
    import json
    from pathlib import Path
    recs = []
    for p in Path('data/evidence_recommendations').glob('*.json'):
        try:
            recs.append(json.loads(p.read_text()))
        except Exception:
            pass
    return sorted(recs, key=lambda r: r.get('attestation_id', ''), reverse=True)
```

**Wire evidence recommendation from pipeline** — in `pipeline.py`, after heavy stage results:
```python
# If beacon + egress both fire AND score >= 0.75 → recommend evidence
high_signal_factors = [f for f in result.factors if f['score'] >= 0.75]
factor_names = {f['name'] for f in high_signal_factors}

if 'beacon' in factor_names and ('egress' in factor_names or 'domain_novelty' in factor_names):
    host = event.get('host', event.get('src_host', ''))
    if host:
        from src.api.routes.evidence import recommend_evidence
        # Fire-and-forget recommendation (no execution)
        asyncio.create_task(recommend_evidence(
            event_id=event.get('id'),
            host=host,
            reason='Beacon + egress/domain-novelty co-fire',
            triggered_by=list(factor_names),
        ))
```

---

### 🟡 MEDIUM — Self-Hosted Docker Improvements

---

#### FIX 9: Add Ollama to Docker Compose
**File**: `docker-compose.yml` (or create `docker-compose.selfhosted.yml`)

```yaml
# Add to existing services block:

  ollama:
    image: ollama/ollama:latest
    container_name: janusec_ollama
    volumes:
      - ollama_models:/root/.ollama
    ports:
      - "11434:11434"
    restart: unless-stopped
    environment:
      - OLLAMA_KEEP_ALIVE=24h
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:11434/api/tags"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s

# Update app service to depend on ollama:
  app:
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
      ollama:
        condition: service_started
    environment:
      - OLLAMA_HOST=http://ollama:11434
      - OLLAMA_MODEL=llama3
      - LLM_PROVIDER=ollama

# Add to volumes:
volumes:
  pgdata:
  redisdata:
  ollama_models:    # ADD THIS
```

**Also add prewarm script** (run once on startup):
```bash
# scripts/prewarm_ollama.sh  — CREATE
#!/bin/bash
echo "Pulling llama3 model..."
curl -s http://ollama:11434/api/pull -d '{"name": "llama3"}' | tail -5
echo "Ollama prewarm complete."
```

---

#### FIX 10: Single-Tenant `.env.example` with MVP Defaults

**File**: `.env.example` — add MVP section at top:

```bash
# ====================================================
# JANUSEC MVP — SELF-HOSTED QUICK START
# ====================================================

# Single-tenant mode (no multi-tenant complexity)
DEFAULT_TENANT=default
STRICT_API_KEY_ENFORCEMENT=1
API_KEY=changeme-replace-this-in-production

# Database (PostgreSQL)
APP_DB_DSN=postgresql://janusec:janusec@db:5432/janusec

# Redis (T2 queue)
REDIS_URL=redis://redis:6379/0

# LLM (Ollama local by default)
LLM_PROVIDER=ollama
OLLAMA_HOST=http://ollama:11434
OLLAMA_MODEL=llama3

# HopGraph persistence
HOPGRAPH_PERSISTENCE_ENABLED=1
HOPGRAPH_DB_PATH=data/hopgraph.db

# AWS (optional — enable what you have)
AWS_CLOUDTRAIL_ENABLED=0
AWS_GUARDDUTY_ENABLED=0
AWS_REGION=us-east-1
# AWS_ROLE_ARN=arn:aws:iam::123456789:role/JanusecReader

# Azure (optional — enable what you have)
AZURE_EVENTHUB_ENABLED=0
# AZURE_EVENTHUB_CONNECTION_STRING=Endpoint=sb://...
# AZURE_EVENTHUB_NAME=janusec-telemetry
# AZURE_TENANT_ID=...
# AZURE_CLIENT_ID=...
# AZURE_CLIENT_SECRET=...

# Pipeline tuning
HEAVY_SKIP_CONFIDENCE=0.8
AWS_POLL_INTERVAL_MINUTES=15
AZURE_POLL_INTERVAL_MINUTES=5

# Evidence gating (recommendations only, no auto-execute)
EVIDENCE_AUTO_EXECUTE=0

# Rate limiting
ALERTS_RL_RPS=50
ALERTS_RL_BURST=100
```

---

### Complete File Change Summary

#### FILES TO CREATE (New)

| File | Purpose | Effort |
|------|---------|--------|
| `src/connectors/azure/__init__.py` | Package init | 5min |
| `src/connectors/azure/base.py` | Base class: auth, checkpoint, canonical_envelope | 1h |
| `src/connectors/azure/event_hub.py` | Event Hub AMQP consumer | 3h |
| `src/connectors/azure/entra_id.py` | Entra ID Graph API connector | 3h |
| `src/connectors/azure/defender_cloud.py` | Defender for Cloud findings | 2h |
| `src/connectors/azure/normalizer.py` | Azure → canonical_envelope mappings | 2h |
| `src/api/routes/connectors.py` | HTTP poll endpoints for AWS + Azure | 2h |
| `src/api/routes/evidence.py` | Evidence recommendation + approval API | 2h |
| `src/api/scheduler.py` | APScheduler for AWS/Azure polling | 1h |
| `scripts/prewarm_ollama.sh` | Ollama model pull on startup | 15min |
| `docs/SELF_HOSTED_QUICKSTART.md` | Setup guide for self-hosted | 2h |
| `docs/connectors/aws_quickstart.md` | AWS connector setup | 1h |
| `docs/connectors/azure_quickstart.md` | Azure Event Hub setup | 1h |

#### FILES TO EDIT (Modify Existing)

| File | Change | Lines to Touch | Effort |
|------|--------|----------------|--------|
| `src/core/event_pipeline/pipeline.py` | Add `_build_correlation_emission()` + call T1 + T2 trigger + evidence recommendation | ~280–330 | 2h |
| `src/api/server.py` | Register connectors + evidence routes, start scheduler on startup | ~50, router includes | 1h |
| `src/core/quality/factor_quality.py` | Add `record_outcome()`, `get_precision()`, `is_suppressed()` | ~53–80 | 1h |
| `src/api/routes/feedback.py` | Wire feedback → `factor_quality.record_outcome()` + persist | ~80–98 | 1h |
| `src/core/event_pipeline/stages/advanced.py` | Filter suppressed factors in correlation stage | correlation stage block | 30min |
| `src/analysis/persona_format.py` | Add `generate_persona_report()` + `_fallback_persona_text()` | append to file | 1h |
| `src/api/report_endpoints.py` | Wire persona LLM into `generate_report()` | ~23, ~40 | 1h |
| `docker-compose.yml` | Add ollama service + volume | add service block | 30min |
| `.env.example` | Add MVP section at top | prepend | 30min |
| `src/api/routes/events.py` | Verify/add Sysmon endpoint ingest (`/endpoints/log_batch`) | check + fix | 1h |
| `requirements.txt` | Add `azure-eventhub>=5.11.0`, `msal>=1.26`, `apscheduler>=3.10` | append | 10min |

#### FILES TO VERIFY (Confirm Working)

| File | What to Verify |
|------|---------------|
| `src/connectors/aws/cloudtrail.py` | `fetch_events()` runs without AWS creds error; checkpoint saved |
| `src/connectors/aws/guardduty.py` | `fetch_findings()` returns canonical format |
| `src/queue/redis_tier2.py` | `enqueue()` / `dequeue()` round-trip works with Redis |
| `src/core/correlation/tier1_summarizer.py` | `summarize_tier1()` works with synthetic `correlation_emission` |
| `src/live/zeek_adapter.py` | `parse_conn()`, `parse_dns()`, `parse_http()`, `parse_ssl()` return valid events |
| `src/connectors/sysmon_evtx.py` | `normalize_sysmon_event()` handles real EVTX XML |
| `src/api/auth_rate_limit.py` | Single API key mode works with `ALERTS_API_KEYS=mykey` |
| `docker-compose.yml` | `docker compose up` starts all services cleanly |

#### FILES TO LEAVE ALONE (Defer / Not MVP)

| File | Reason |
|------|--------|
| `src/connectors/gcp/` | GCP is sprint 2, not MVP |
| `src/artifact/memory_acquisition.py` | Evidence model fine; API wrapper created instead |
| `src/core/event_pipeline/stages/network.py:pcap_session` | Heavy PCAP analysis deferred |
| `src/modules/adaptive_tuner.py` | sklearn-based ML tuning is post-MVP |
| Multi-tenancy (`src/api/tenant_helpers.py`) | Works; bypass with `DEFAULT_TENANT=default` |
| `infra/terraform/` | Self-hosted Docker Compose is MVP infra |
| `frontend/react/` | Static HTML frontend is MVP |

---

## Week-by-Week Sprint Plan

### Week 1: Pipeline End-to-End + Self-Hosted Boot

**Goal**: `docker compose up` → send event → get T1 decision → see it in decisions stream

| Task | File(s) | Who | Day |
|------|---------|-----|-----|
| Fix `_build_correlation_emission()` in pipeline | `pipeline.py` | Dev | 1 |
| Wire T1 call in `process_event()` | `pipeline.py` | Dev | 1 |
| Verify T2 enqueue from pipeline (high severity) | `pipeline.py`, `redis_tier2.py` | Dev | 2 |
| Verify Sysmon `/endpoints/log_batch` path | `routes/events.py` | Dev | 2 |
| Add Ollama to docker-compose + prewarm script | `docker-compose.yml` | Dev | 3 |
| Update `.env.example` with MVP defaults | `.env.example` | Dev | 3 |
| Smoke test: POST event → check decision in DB | `tests/test_smoke_e2e.py` | Dev | 4 |
| Smoke test: Zeek event → pipeline → T1 | `tests/test_smoke_zeek.py` | Dev | 5 |

### Week 2: Cloud Connectors (AWS HTTP + Azure Build)

**Goal**: AWS CloudTrail polling works; Azure Entra ID connector ingesting

| Task | File(s) | Who | Day |
|------|---------|-----|-----|
| Create Azure connector base + normalizer | `azure/base.py`, `normalizer.py` | Dev | 1 |
| Build Entra ID connector (Graph API) | `azure/entra_id.py` | Dev | 2 |
| Build Event Hub consumer | `azure/event_hub.py` | Dev | 3 |
| Create HTTP poll route for AWS + Azure | `routes/connectors.py` | Dev | 3 |
| Create APScheduler for background polling | `api/scheduler.py` | Dev | 4 |
| Register routes + scheduler in server.py | `api/server.py` | Dev | 4 |
| Test AWS CloudTrail poll → pipeline → decision | manual test | Dev | 5 |
| Test Azure Entra ID poll → sign-in alert | manual test | Dev | 5 |

### Week 3: FP Reduction + Persona Reports

**Goal**: Analyst can label FPs; reports show all 3 personas with LLM text

| Task | File(s) | Who | Day |
|------|---------|-----|-----|
| Wire feedback → `factor_quality.record_outcome()` | `routes/feedback.py`, `factor_quality.py` | Dev | 1 |
| Add suppression check to correlation stage | `stages/advanced.py` | Dev | 1 |
| Add `generate_persona_report()` to persona_format | `persona_format.py` | Dev | 2 |
| Wire persona LLM into report_endpoints | `report_endpoints.py` | Dev | 2 |
| Create evidence recommendation API | `routes/evidence.py` | Dev | 3 |
| Wire evidence trigger from pipeline heavy stages | `pipeline.py` | Dev | 3 |
| Register evidence routes in server.py | `api/server.py` | Dev | 4 |
| Test: mark FP → verify factor suppressed next run | manual test | Dev | 5 |
| Test: generate analyst + manager + forensics report | manual test | Dev | 5 |

### Week 4: Hardening + Go-Live

**Goal**: Security hardened, documented, first client onboarded

| Task | File(s) | Who | Day |
|------|---------|-----|-----|
| Harden auth — remove PYTEST permissive path from prod | `auth_rate_limit.py` | Dev | 1 |
| Add `/health` liveness + readiness endpoints | `server.py` | Dev | 1 |
| Full smoke CI workflow | `.github/workflows/smoke.yml` | Dev | 2 |
| Bandit security scan clean | `.github/workflows/bandit.yml` | Dev | 2 |
| Write self-hosted quickstart doc | `docs/SELF_HOSTED_QUICKSTART.md` | Dev | 3 |
| Write AWS connector doc | `docs/connectors/aws_quickstart.md` | Dev | 3 |
| Write Azure connector doc | `docs/connectors/azure_quickstart.md` | Dev | 3 |
| First client onboarding dry-run | — | Dev | 4–5 |

---

## New Dependencies to Add

**File**: `requirements.txt`

```
# Azure connectors
azure-eventhub>=5.11.0
msal>=1.26.0

# AWS connectors (likely already present)
boto3>=1.34.0

# Scheduler (background polling)
apscheduler>=3.10.0

# PDF reports (likely already present)
weasyprint>=60.0

# Local LLM (already present)
# Ollama runs as a Docker service, no Python package needed
```

---

## Environment Variables Reference (Full MVP)

```bash
# Core
DEFAULT_TENANT=default
API_KEY=<generate-with-openssl-rand-hex-32>
STRICT_API_KEY_ENFORCEMENT=1
APP_DB_DSN=postgresql://janusec:janusec@db:5432/janusec
REDIS_URL=redis://redis:6379/0

# LLM
LLM_PROVIDER=ollama
OLLAMA_HOST=http://ollama:11434
OLLAMA_MODEL=llama3
LLM_TENANT_BUDGET=50.0  # USD cap per tenant per month

# Pipeline
HEAVY_SKIP_CONFIDENCE=0.8
FACTOR_FP_RATIO_THRESHOLD=0.8
FACTOR_MIN_OBSERVATIONS=10

# HopGraph
HOPGRAPH_PERSISTENCE_ENABLED=1
HOPGRAPH_DB_PATH=data/hopgraph.db

# AWS (toggle per source)
AWS_CLOUDTRAIL_ENABLED=1
AWS_GUARDDUTY_ENABLED=1
AWS_REGION=us-east-1
AWS_POLL_INTERVAL_MINUTES=15
# AWS_ROLE_ARN=arn:aws:iam::ACCOUNT:role/JanusecReader

# Azure (toggle per source)
AZURE_EVENTHUB_ENABLED=0
AZURE_EVENTHUB_CONNECTION_STRING=
AZURE_EVENTHUB_NAME=janusec-telemetry
AZURE_ENTRA_ENABLED=0
AZURE_TENANT_ID=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
AZURE_POLL_INTERVAL_MINUTES=5

# Scheduler
AWS_POLL_INTERVAL_MINUTES=15
AZURE_POLL_INTERVAL_MINUTES=5

# Evidence gating
EVIDENCE_AUTO_EXECUTE=0  # NEVER auto-execute; always require analyst approval

# Rate limiting
ALERTS_RL_RPS=50
ALERTS_RL_BURST=100
ALERTS_API_KEYS=  # same as API_KEY for MVP
```

---

## Test Coverage Required Before Go-Live

```python
# Minimum test coverage for MVP:

tests/
├── test_smoke_e2e.py              # POST event → pipeline → T1 decision → assert score
├── test_smoke_zeek.py             # Zeek conn event → beacon stage → decision
├── test_smoke_sysmon.py           # Sysmon EVTX → parent_child → decision
├── test_aws_cloudtrail_poll.py    # Mock boto3 → poll → ingest → decision
├── test_azure_entra_poll.py       # Mock Graph API → poll → ingest → decision
├── test_t1_summarizer.py          # Verify T1 output format with synthetic emission
├── test_t2_queue.py               # Enqueue → dequeue → LLM call → result persisted
├── test_feedback_fp_suppression.py # Mark FP → verify factor suppressed → re-run
├── test_persona_report.py         # Generate analyst/manager/forensics with fallback
├── test_evidence_recommendation.py # Recommend → approve → list
└── test_auth_api_key.py           # Valid key → 200; invalid → 401; no key → 401
```

---

## ASCII: MVP Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     TELEMETRY SOURCES                           │
│                                                                  │
│  AWS CloudTrail ──┐  Azure Entra ──┐  Zeek ──┐  Sysmon ──┐     │
│  AWS GuardDuty ───┤  Azure Defender┤  (PCAP) │  (EVTX)   │     │
│  AWS VPC Flow ────┘  Azure Evt Hub ┘          │            │     │
│                                               │            │     │
│  Poll every 15min (scheduler)           Streaming      Batch    │
└───────────┬───────────────────────────────────┬────────────┬────┘
            │                                   │            │
            ▼                                   ▼            ▼
┌───────────────────────────────────────────────────────────────┐
│                      INGEST LAYER                              │
│  /api/v1/connectors/aws/poll   ──► pipeline.process_event()   │
│  /api/v1/connectors/azure/poll ──► pipeline.process_event()   │
│  /api/v1/ingest/stream         ──► pipeline.process_event()   │
│  /api/v1/endpoints/log_batch   ──► normalize_sysmon + pipeline│
│  /api/v1/webhooks/*            ──► HMAC guard + pipeline      │
└───────────────────────────┬───────────────────────────────────┘
                            │
                            ▼
┌───────────────────────────────────────────────────────────────┐
│                  EVENT PIPELINE (33 stages)                    │
│                                                                │
│  FAST (24) ──────────────────────────────────────────────►    │
│  baseline, regex, parent_child, endpoint, auth_burst,         │
│  identity, graph, threat_intel, supply_chain, sbom,            │
│  hunt_lanes, correlation, mapping, cluster_dedupe, embedding  │
│                                                                │
│  HEAVY (5) ── gated: confidence < 0.8 OR explicit evidence ── │
│  beacon (C2), egress (exfil), domain_novelty, pcap, binary    │
│                                                                │
│  After stages: _build_correlation_emission()  ◄── FIX 1       │
│                                                                │
│  FP Filter: suppressed factors removed from emission          │
└───────────────────────────┬───────────────────────────────────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
              ▼             ▼             ▼
    ┌──────────────┐ ┌────────────┐ ┌──────────────────┐
    │ T1 SUMMARY   │ │ T2 QUEUE   │ │ EVIDENCE GATE    │
    │ (immediate)  │ │ (async)    │ │ (recommend only) │
    │              │ │            │ │                  │
    │ Always fires │ │ High sev   │ │ beacon + egress  │
    │ No LLM       │ │ Ambiguous  │ │ → recommend KAPE │
    │ Deterministic│ │ Explicit   │ │ analyst approves │
    └──────┬───────┘ └─────┬──────┘ └────────┬─────────┘
           │               │                 │
           ▼               ▼                 ▼
    ┌──────────────────────────────────────────────────┐
    │                 DECISIONS DB (PostgreSQL)         │
    │  verdict, confidence, t1_summary, factors        │
    │  tenant_id, event_id, custody_hash               │
    └──────────────────┬───────────────────────────────┘
                       │
           ┌───────────┼───────────┐
           │           │           │
           ▼           ▼           ▼
    ┌───────────┐ ┌─────────┐ ┌──────────┐
    │  ANALYST  │ │ MANAGER │ │FORENSICS │
    │  REPORT   │ │ REPORT  │ │ REPORT   │
    │           │ │         │ │          │
    │ Technical │ │Business │ │Checklist │
    │ 4-6 sent. │ │ impact  │ │+ timeline│
    └───────────┘ └─────────┘ └──────────┘
           │
           ▼
    ┌───────────────────────────────────────────────────┐
    │               FEEDBACK LOOP                       │
    │  POST /api/v1/feedback                            │
    │  label: mark_legit | mark_suspicious | malicious  │
    │         ↓                                         │
    │  factor_quality.record_outcome(factor, is_tp)     │
    │         ↓                                         │
    │  is_suppressed() used in next pipeline run        │
    │  (FP rate > 80% → suppress factor)               │
    └───────────────────────────────────────────────────┘
```

---

*Document generated: 2026-03-27 | MVP target: 3–4 weeks | Branch: feat/webhook-guard-middleware-only-verification*
