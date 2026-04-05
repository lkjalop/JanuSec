# 🛠️ JANUSEC PLATFORM IMPLEMENTATION ROADMAP - DETAILED
**Date:** 2025-01-15
**Type:** Comprehensive Gap Analysis & Code-Level Implementation Guide
**Priority:** Critical Gaps → High-Value Features → Nice-to-Haves

---

## 📋 TABLE OF CONTENTS

1. [Production Metrics & Dashboards](#1-production-metrics--dashboards)
2. [Correlation Rules - Stub to Production](#2-correlation-rules---stub-to-production)
3. [Closed-Loop Learning & Online Training](#3-closed-loop-learning--online-training)
4. [Email Domain Enhancement](#4-email-domain-enhancement)
5. [IAM Domain Enhancement](#5-iam-domain-enhancement)
6. [Cloud Domain Enhancement](#6-cloud-domain-enhancement)
7. [Threat Intel Integration](#7-threat-intel-integration)
8. [Horizontal Scaling & HA](#8-horizontal-scaling--ha)
9. [Security Hardening](#9-security-hardening)
10. [Testing Infrastructure](#10-testing-infrastructure)

---

## 1. PRODUCTION METRICS & DASHBOARDS

### **Problem Statement:**
❌ No dashboard showing "Before: 1000 FP/day → After: 100 FP/day"
❌ No precision/recall benchmarks
❌ No A/B test results comparing suppression on/off

### **Files to Create:**

#### 1.1. Precision/Recall Tracking Repository
**File:** `src/repositories/precision_metrics_repo.py` (NEW)

```python
"""
Precision/Recall metrics tracking for production FP reduction validation.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import asyncpg

@dataclass
class PrecisionMetric:
    """Daily precision/recall metrics."""
    metric_date: datetime
    tenant_id: str
    total_alerts: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    suppression_enabled: bool

    @classmethod
    def calculate(cls, tp: int, fp: int, tn: int, fn: int,
                  tenant: str, date: datetime, suppression: bool) -> 'PrecisionMetric':
        """Calculate precision/recall from confusion matrix."""
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        return cls(
            metric_date=date,
            tenant_id=tenant,
            total_alerts=tp + fp + tn + fn,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            suppression_enabled=suppression
        )


class PrecisionMetricsRepo:
    """Repository for precision/recall metrics."""

    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    async def record_daily_metrics(self, metric: PrecisionMetric) -> int:
        """Record daily precision/recall metrics."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO precision_metrics (
                    metric_date, tenant_id, total_alerts,
                    true_positives, false_positives, true_negatives, false_negatives,
                    precision, recall, f1_score, suppression_enabled
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                RETURNING id
            """, metric.metric_date, metric.tenant_id, metric.total_alerts,
                metric.true_positives, metric.false_positives,
                metric.true_negatives, metric.false_negatives,
                metric.precision, metric.recall, metric.f1_score,
                metric.suppression_enabled)
            return row['id']

    async def get_fp_trend(self, tenant_id: str, days: int = 30) -> list:
        """Get FP trend over time."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT metric_date, false_positives, total_alerts,
                       (false_positives::float / total_alerts) as fp_rate
                FROM precision_metrics
                WHERE tenant_id = $1
                  AND metric_date >= NOW() - INTERVAL '{days} days'
                ORDER BY metric_date ASC
            """, tenant_id, days=days)
            return [dict(r) for r in rows]

    async def compare_suppression(self, tenant_id: str, days: int = 7) -> dict:
        """Compare metrics with suppression on vs off."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT suppression_enabled,
                       AVG(precision) as avg_precision,
                       AVG(recall) as avg_recall,
                       AVG(f1_score) as avg_f1,
                       SUM(false_positives) as total_fp,
                       SUM(total_alerts) as total_alerts
                FROM precision_metrics
                WHERE tenant_id = $1
                  AND metric_date >= NOW() - INTERVAL '{days} days'
                GROUP BY suppression_enabled
            """, tenant_id, days=days)

            result = {'suppression_on': None, 'suppression_off': None}
            for row in rows:
                key = 'suppression_on' if row['suppression_enabled'] else 'suppression_off'
                result[key] = dict(row)
            return result
```

#### 1.2. Migration for Precision Metrics Table
**File:** `db/migrations/010_precision_metrics.sql` (NEW)

```sql
-- Precision/Recall metrics tracking table
CREATE TABLE IF NOT EXISTS precision_metrics (
    id SERIAL PRIMARY KEY,
    metric_date DATE NOT NULL,
    tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
    total_alerts INTEGER NOT NULL,
    true_positives INTEGER NOT NULL DEFAULT 0,
    false_positives INTEGER NOT NULL DEFAULT 0,
    true_negatives INTEGER NOT NULL DEFAULT 0,
    false_negatives INTEGER NOT NULL DEFAULT 0,
    precision REAL NOT NULL,
    recall REAL NOT NULL,
    f1_score REAL NOT NULL,
    suppression_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_precision_metrics_date ON precision_metrics(metric_date DESC);
CREATE INDEX idx_precision_metrics_tenant ON precision_metrics(tenant_id, metric_date DESC);

-- FP reduction summary view
CREATE OR REPLACE VIEW fp_reduction_summary AS
SELECT
    tenant_id,
    metric_date,
    false_positives,
    total_alerts,
    (false_positives::float / NULLIF(total_alerts, 0)) as fp_rate,
    LAG(false_positives) OVER (PARTITION BY tenant_id ORDER BY metric_date) as prev_day_fp,
    (false_positives - LAG(false_positives) OVER (PARTITION BY tenant_id ORDER BY metric_date)) as fp_delta
FROM precision_metrics
ORDER BY tenant_id, metric_date DESC;
```

#### 1.3. FP Reduction Dashboard API Endpoint
**File:** `src/api/metrics_status_endpoints.py` (MODIFY - add new endpoints)

**Lines to add after line 150:**

```python
@router.get("/fp_reduction_trend")
async def fp_reduction_trend(
    tenant_id: str = Depends(get_tenant_id),
    days: int = Query(30, ge=1, le=90),
    db: asyncpg.Pool = Depends(get_db_pool)
):
    """
    Get FP reduction trend over time.

    Returns daily FP counts and rates for visualization.
    """
    from src.repositories.precision_metrics_repo import PrecisionMetricsRepo

    repo = PrecisionMetricsRepo(db)
    trend_data = await repo.get_fp_trend(tenant_id, days)

    if not trend_data:
        return {
            "tenant_id": tenant_id,
            "days": days,
            "data": [],
            "summary": {
                "avg_fp_rate": 0.0,
                "total_alerts": 0,
                "total_fp": 0
            }
        }

    total_fp = sum(d['false_positives'] for d in trend_data)
    total_alerts = sum(d['total_alerts'] for d in trend_data)
    avg_fp_rate = total_fp / total_alerts if total_alerts > 0 else 0.0

    return {
        "tenant_id": tenant_id,
        "days": days,
        "data": trend_data,
        "summary": {
            "avg_fp_rate": avg_fp_rate,
            "total_alerts": total_alerts,
            "total_fp": total_fp,
            "improvement_pct": calculate_improvement(trend_data)
        }
    }


@router.get("/suppression_ab_test")
async def suppression_ab_test(
    tenant_id: str = Depends(get_tenant_id),
    days: int = Query(7, ge=1, le=30),
    db: asyncpg.Pool = Depends(get_db_pool)
):
    """
    A/B test results: suppression on vs off.

    Compares precision/recall/F1 with and without factor suppression.
    """
    from src.repositories.precision_metrics_repo import PrecisionMetricsRepo

    repo = PrecisionMetricsRepo(db)
    comparison = await repo.compare_suppression(tenant_id, days)

    if not comparison['suppression_on'] or not comparison['suppression_off']:
        raise HTTPException(
            status_code=404,
            detail="Insufficient data for A/B test comparison. Need data with suppression both on and off."
        )

    on = comparison['suppression_on']
    off = comparison['suppression_off']

    return {
        "tenant_id": tenant_id,
        "days": days,
        "suppression_on": {
            "avg_precision": on['avg_precision'],
            "avg_recall": on['avg_recall'],
            "avg_f1": on['avg_f1'],
            "total_fp": on['total_fp'],
            "fp_rate": on['total_fp'] / on['total_alerts'] if on['total_alerts'] > 0 else 0
        },
        "suppression_off": {
            "avg_precision": off['avg_precision'],
            "avg_recall": off['avg_recall'],
            "avg_f1": off['avg_f1'],
            "total_fp": off['total_fp'],
            "fp_rate": off['total_fp'] / off['total_alerts'] if off['total_alerts'] > 0 else 0
        },
        "improvement": {
            "precision_gain": on['avg_precision'] - off['avg_precision'],
            "recall_change": on['avg_recall'] - off['avg_recall'],
            "f1_gain": on['avg_f1'] - off['avg_f1'],
            "fp_reduction_pct": ((off['total_fp'] - on['total_fp']) / off['total_fp'] * 100) if off['total_fp'] > 0 else 0
        }
    }


def calculate_improvement(trend_data: list) -> float:
    """Calculate % improvement from first week to last week."""
    if len(trend_data) < 7:
        return 0.0

    first_week = trend_data[:7]
    last_week = trend_data[-7:]

    first_fp_rate = sum(d['false_positives'] for d in first_week) / sum(d['total_alerts'] for d in first_week)
    last_fp_rate = sum(d['false_positives'] for d in last_week) / sum(d['total_alerts'] for d in last_week)

    improvement = ((first_fp_rate - last_fp_rate) / first_fp_rate * 100) if first_fp_rate > 0 else 0.0
    return improvement
```

#### 1.4. Automated Daily Metrics Collection
**File:** `src/background/daily_metrics_collector.py` (NEW)

```python
"""
Background task to calculate daily precision/recall metrics.
Runs at midnight UTC to aggregate previous day's decisions.
"""
import asyncio
from datetime import datetime, timedelta
from src.repositories.precision_metrics_repo import PrecisionMetricsRepo, PrecisionMetric
from src.repositories.decisions_repo import get_decisions_repo
from src.db.database import get_pool

async def calculate_daily_precision_recall(tenant_id: str, date: datetime, pool) -> PrecisionMetric:
    """
    Calculate precision/recall for a specific day.

    Logic:
    - Query all decisions for the day
    - Count analyst feedback: TP (confirmed), FP (dismissed), FN (missed)
    - TN is harder to measure (benign events that didn't alert) - estimate from event volume
    """
    decisions_repo = get_decisions_repo(pool)

    # Get all decisions for the day
    start_of_day = date.replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_day = start_of_day + timedelta(days=1)

    decisions = await decisions_repo.get_decisions_by_date_range(
        tenant_id, start_of_day, end_of_day
    )

    # Count based on feedback
    tp = sum(1 for d in decisions if d.get('feedback') == 'true_positive')
    fp = sum(1 for d in decisions if d.get('feedback') == 'false_positive')
    fn = sum(1 for d in decisions if d.get('feedback') == 'false_negative')

    # Estimate TN from total events minus alerted events
    # This requires event volume tracking (may need to add)
    total_events = await get_daily_event_count(tenant_id, date, pool)
    tn = total_events - len(decisions) - fn  # Rough estimate

    # Check if suppression was enabled (query config table)
    suppression_enabled = await is_suppression_enabled(tenant_id, date, pool)

    return PrecisionMetric.calculate(
        tp=tp, fp=fp, tn=tn, fn=fn,
        tenant=tenant_id, date=date,
        suppression=suppression_enabled
    )


async def daily_metrics_task():
    """Background task that runs daily at midnight UTC."""
    pool = await get_pool()
    metrics_repo = PrecisionMetricsRepo(pool)

    while True:
        # Calculate for yesterday
        yesterday = datetime.utcnow().date() - timedelta(days=1)

        # Get all active tenants
        tenants = await get_active_tenants(pool)

        for tenant_id in tenants:
            try:
                metric = await calculate_daily_precision_recall(tenant_id, yesterday, pool)
                await metrics_repo.record_daily_metrics(metric)
                print(f"[DailyMetrics] Recorded metrics for {tenant_id} on {yesterday}: P={metric.precision:.2f} R={metric.recall:.2f}")
            except Exception as e:
                print(f"[DailyMetrics] Error for {tenant_id}: {e}")

        # Sleep until next midnight UTC
        now = datetime.utcnow()
        tomorrow_midnight = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        sleep_seconds = (tomorrow_midnight - now).total_seconds()
        await asyncio.sleep(sleep_seconds)


# Helper functions (implement in respective repos)
async def get_daily_event_count(tenant_id: str, date: datetime, pool) -> int:
    """Get total event count for a day."""
    # TODO: Query events table or use metrics
    return 10000  # Placeholder

async def is_suppression_enabled(tenant_id: str, date: datetime, pool) -> bool:
    """Check if factor suppression was enabled on a given date."""
    # TODO: Query config history table
    return True  # Assume enabled by default

async def get_active_tenants(pool) -> list:
    """Get list of active tenant IDs."""
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT DISTINCT tenant_id FROM decisions WHERE created_at > NOW() - INTERVAL '7 days'")
        return [r['tenant_id'] for r in rows]
```

#### 1.5. Grafana Dashboard JSON
**File:** `dashboards/fp_reduction_dashboard.json` (NEW)

```json
{
  "dashboard": {
    "title": "FP Reduction & Precision Tracking",
    "panels": [
      {
        "id": 1,
        "title": "FP Rate Trend (30 days)",
        "type": "graph",
        "targets": [
          {
            "expr": "SELECT metric_date, (false_positives::float / total_alerts) as fp_rate FROM precision_metrics WHERE tenant_id = '$tenant' AND metric_date >= NOW() - INTERVAL '30 days' ORDER BY metric_date",
            "format": "time_series"
          }
        ],
        "yaxes": [{"format": "percentunit", "label": "FP Rate"}]
      },
      {
        "id": 2,
        "title": "Precision vs Recall",
        "type": "graph",
        "targets": [
          {
            "expr": "SELECT metric_date, precision, recall FROM precision_metrics WHERE tenant_id = '$tenant' ORDER BY metric_date",
            "format": "time_series"
          }
        ]
      },
      {
        "id": 3,
        "title": "Suppression Impact (A/B Test)",
        "type": "bargauge",
        "targets": [
          {
            "expr": "SELECT suppression_enabled, AVG(precision) as avg_precision FROM precision_metrics WHERE tenant_id = '$tenant' GROUP BY suppression_enabled"
          }
        ]
      },
      {
        "id": 4,
        "title": "Before/After FP Count",
        "type": "stat",
        "targets": [
          {
            "expr": "SELECT SUM(false_positives) FROM precision_metrics WHERE tenant_id = '$tenant' AND metric_date < '2025-01-01'",
            "legendFormat": "Before"
          },
          {
            "expr": "SELECT SUM(false_positives) FROM precision_metrics WHERE tenant_id = '$tenant' AND metric_date >= '2025-01-01'",
            "legendFormat": "After"
          }
        ]
      }
    ],
    "templating": {
      "list": [
        {
          "name": "tenant",
          "type": "query",
          "query": "SELECT DISTINCT tenant_id FROM precision_metrics",
          "current": {"value": "default"}
        }
      ]
    }
  }
}
```

---

## 2. CORRELATION RULES - STUB TO PRODUCTION

### **Problem Statement:**
❌ 180+ rules registered but most marked "Placeholder"
❌ Basic pattern matching, not sophisticated logic
❌ No evidence of production validation

### **Files to Fix:**

#### 2.1. Week1 Rules Enhancement

**File:** `src/core/correlation/rules/week1/office_macro_chain.py`

**Current Code (lines 10-30):**
```python
"""Placeholder rule: Office macro spawns PowerShell."""

def office_macro_spawn_powershell(evidence_env):
    """Basic placeholder detection."""
    factors = evidence_env.factors

    if 'lane_process_lineage:office_macro_spawn_powershell' in factors:
        return ['corr_office_macro_ps']
    return []
```

**REPLACE WITH (sophisticated logic):**

```python
"""
Production-grade Office macro → PowerShell correlation.

Detects:
1. Office process (Word, Excel, PowerPoint) spawning PowerShell
2. With suspicious command-line patterns (encoded, download, invoke)
3. Followed by network activity to rare domains
4. Temporal correlation within 60 seconds
"""
import re
from datetime import datetime, timedelta

# Suspicious PowerShell patterns
SUSPICIOUS_PS_PATTERNS = [
    r'-enc(oded)?command',
    r'-nop(rofile)?',
    r'-w(indowstyle)?\s+hidden',
    r'downloadstring',
    r'invoke-expression',
    r'invoke-webrequest',
    r'iex\s*\(',
    r'new-object\s+net\.webclient',
    r'start-bitstransfer',
]

def office_macro_spawn_powershell(evidence_env):
    """
    Sophisticated Office → PowerShell detection with context.

    Scoring:
    - Base: Office spawns PowerShell (+0.15)
    - Encoded command (+0.20)
    - Hidden window (+0.10)
    - Network to rare domain within 60s (+0.25)
    - User clicked "Enable Macros" button (+0.15)
    """
    factors = evidence_env.factors
    meta = evidence_env.metadata
    host = evidence_env.host

    score = 0.0
    reasons = []

    # Base detection: Office → PowerShell lineage
    if 'lane_process_lineage:office_macro_spawn_powershell' not in factors:
        return []

    score += 0.15
    reasons.append("Office process spawned PowerShell")

    # Check command line for suspicious patterns
    cmdline = meta.get('command_line', '').lower()
    for pattern in SUSPICIOUS_PS_PATTERNS:
        if re.search(pattern, cmdline, re.IGNORECASE):
            score += 0.20
            reasons.append(f"Suspicious PowerShell pattern: {pattern}")
            break  # Only count once

    # Check for hidden window
    if '-windowstyle' in cmdline and 'hidden' in cmdline:
        score += 0.10
        reasons.append("PowerShell launched with hidden window")

    # Temporal correlation: network activity within 60 seconds
    event_time = evidence_env.timestamp
    recent_network = check_recent_network_activity(host, event_time, window_seconds=60)

    if recent_network and 'net:domain_rare' in factors:
        score += 0.25
        reasons.append("Network activity to rare domain within 60s")

    # User interaction: "Enable Macros" click
    if 'endpoint:macro_enabled' in factors:
        score += 0.15
        reasons.append("User explicitly enabled macros")

    # Emit correlation factor with score and reasoning
    if score >= 0.35:  # Threshold for correlation
        return [{
            'factor': 'corr_office_macro_ps',
            'score': score,
            'reasons': reasons,
            'mitre': ['T1566.001', 'T1059.001'],  # Phishing: Spearphishing Attachment, PowerShell
            'confidence': min(score, 0.95)
        }]

    return []


def check_recent_network_activity(host: str, timestamp: datetime, window_seconds: int) -> bool:
    """
    Check if host had network activity in recent time window.
    Query HopGraph or event store.
    """
    from src.core.graph.hopgraph_lite import get_hopgraph

    graph = get_hopgraph()
    start_time = timestamp - timedelta(seconds=window_seconds)

    # Query for network edges from this host in time window
    edges = graph.get_edges_by_src(f"host:{host}", start_time=start_time, end_time=timestamp)
    network_edges = [e for e in edges if e.etype in ('tcp_flow', 'dns_query', 'http_request')]

    return len(network_edges) > 0
```

**Add Test:**
**File:** `tests/test_correlation_office_macro.py` (NEW)

```python
"""Test production Office macro correlation rule."""
import pytest
from datetime import datetime, timedelta
from src.core.correlation.rules.week1.office_macro_chain import office_macro_spawn_powershell
from src.core.hunt.evidence_envelope import EvidenceEnvelope

def test_office_macro_basic():
    """Test basic Office → PowerShell detection."""
    env = EvidenceEnvelope(
        event_id='test-1',
        timestamp=datetime.utcnow(),
        host='wkstn-22',
        factors=['lane_process_lineage:office_macro_spawn_powershell'],
        metadata={'command_line': 'powershell.exe -file benign.ps1'}
    )

    result = office_macro_spawn_powershell(env)
    assert len(result) == 1
    assert result[0]['factor'] == 'corr_office_macro_ps'
    assert result[0]['score'] == 0.15  # Base score only


def test_office_macro_encoded_command():
    """Test encoded PowerShell command increases score."""
    env = EvidenceEnvelope(
        event_id='test-2',
        timestamp=datetime.utcnow(),
        host='wkstn-22',
        factors=['lane_process_lineage:office_macro_spawn_powershell'],
        metadata={'command_line': 'powershell.exe -encodedcommand SQBFAF...'}
    )

    result = office_macro_spawn_powershell(env)
    assert result[0]['score'] >= 0.35  # Base + encoded
    assert 'Suspicious PowerShell pattern' in result[0]['reasons'][1]


def test_office_macro_with_network():
    """Test temporal correlation with network activity."""
    # Mock HopGraph to return network edges
    # (Implementation depends on HopGraph mocking strategy)
    pass  # TODO: Add HopGraph mock


def test_office_macro_below_threshold():
    """Test that low-confidence events don't emit correlation."""
    env = EvidenceEnvelope(
        event_id='test-3',
        timestamp=datetime.utcnow(),
        host='wkstn-22',
        factors=[],  # No base factor
        metadata={}
    )

    result = office_macro_spawn_powershell(env)
    assert len(result) == 0  # Below threshold
```

#### 2.2. Implement Remaining Week1 Rules (5 total)

**Files to enhance with same pattern:**
1. `src/core/correlation/rules/week1/amsi_bypass.py` - Add AMSI bypass detection logic
2. `src/core/correlation/rules/week1/powershell_encoded.py` - Detect Base64 encoded payloads
3. `src/core/correlation/rules/week1/scheduled_task_lolbin.py` - Detect scheduled task abuse
4. `src/core/correlation/rules/week1/office_spawn_ps.py` - Generic Office → PowerShell (merge with macro_chain)

**Each rule should follow template:**
```python
# 1. Define suspicious patterns/IOCs
# 2. Check base factor presence
# 3. Add contextual scoring (command-line, user, time-of-day)
# 4. Temporal correlation (check HopGraph for related events)
# 5. Return scored factor with reasoning + MITRE mapping
# 6. Write 3-5 unit tests
```

---

#### 2.3. Email Domain Correlation Rules

**File:** `src/core/correlation/rules/email/bec_chain.py` (NEW)

```python
"""
Business Email Compromise (BEC) correlation chain.

Detects:
1. Email from lookalike domain (homograph/typosquatting)
2. Requesting urgent wire transfer or credential reset
3. From external domain impersonating executive
4. User clicks link or replies with sensitive info
"""
import re
from src.core.correlation.factor_constants import CORR_BEC_EXECUTIVE_IMPERSONATION

# Executive title keywords
EXEC_KEYWORDS = ['ceo', 'cfo', 'president', 'vp', 'vice president', 'director', 'executive']

# Urgency keywords
URGENCY_KEYWORDS = ['urgent', 'asap', 'immediately', 'wire transfer', 'reset password', 'verify account']

def bec_executive_impersonation(evidence_env):
    """
    Detect BEC via executive impersonation.

    Scoring:
    - Homograph domain (+0.25)
    - Executive title in display name (+0.20)
    - Urgency keywords in subject/body (+0.15)
    - External domain claiming to be internal exec (+0.30)
    - User replied or clicked link (+0.20)
    """
    factors = evidence_env.factors
    meta = evidence_env.metadata

    score = 0.0
    reasons = []

    # Base: homograph domain detected
    if 'email:domain_homograph' not in factors:
        return []

    score += 0.25
    reasons.append("Homograph domain detected")

    # Check display name for executive title
    display_name = meta.get('from_display_name', '').lower()
    if any(kw in display_name for kw in EXEC_KEYWORDS):
        score += 0.20
        reasons.append("Executive title in sender display name")

    # Check subject/body for urgency
    subject = meta.get('subject', '').lower()
    body = meta.get('body', '').lower()
    if any(kw in subject or kw in body for kw in URGENCY_KEYWORDS):
        score += 0.15
        reasons.append("Urgency keywords in email content")

    # External domain claiming to be internal
    from_domain = meta.get('from_domain', '')
    org_domain = meta.get('org_domain', 'example.com')

    if from_domain != org_domain and display_name_contains_org(display_name, org_domain):
        score += 0.30
        reasons.append("External sender impersonating internal executive")

    # User interaction (replied or clicked)
    if 'email:user_replied' in factors or 'email:link_clicked' in factors:
        score += 0.20
        reasons.append("User interacted with suspicious email")

    if score >= 0.50:  # High threshold for BEC
        return [{
            'factor': CORR_BEC_EXECUTIVE_IMPERSONATION,
            'score': score,
            'reasons': reasons,
            'mitre': ['T1566.002'],  # Phishing: Spearphishing Link
            'recommended_action': 'Block sender domain, quarantine email, notify user',
            'confidence': min(score, 0.98)
        }]

    return []


def display_name_contains_org(display_name: str, org_domain: str) -> bool:
    """Check if display name references organization."""
    org_name = org_domain.split('.')[0]  # e.g., "example" from "example.com"
    return org_name.lower() in display_name.lower()
```

---

## 3. CLOSED-LOOP LEARNING & ONLINE TRAINING

### **Problem Statement:**
❌ Feedback loop exists but doesn't retrain models
❌ Adaptive tuner has drift detection but no retraining
❌ Analysts vote on factors but weights don't update automatically

### **Files to Modify/Create:**

#### 3.1. Factor Weight Retraining Module
**File:** `src/ml/factor_weight_learner.py` (NEW)

```python
"""
Online learning for factor weights based on analyst feedback.

Approach:
1. Collect analyst votes (factor → TP/FP)
2. Use logistic regression to learn optimal weights
3. Gradually update factor weights (with safety guardrails)
4. A/B test new weights before deploying
"""
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from typing import Dict, List
import asyncio

class FactorWeightLearner:
    """Online learner for factor weights."""

    def __init__(self, current_weights: Dict[str, float]):
        self.current_weights = current_weights
        self.scaler = StandardScaler()
        self.model = LogisticRegression(penalty='l2', C=1.0, max_iter=1000)
        self.training_buffer = []  # Store (factors, label) tuples
        self.min_samples_for_update = 100  # Require 100 samples before retraining
        self.max_weight_delta = 0.05  # Max 5% weight change per update (safety)

    def add_feedback(self, event_factors: List[str], label: int):
        """
        Add analyst feedback.

        Args:
            event_factors: List of factors that fired for this event
            label: 1 for TP, 0 for FP
        """
        self.training_buffer.append((event_factors, label))

    def should_retrain(self) -> bool:
        """Check if we have enough samples to retrain."""
        return len(self.training_buffer) >= self.min_samples_for_update

    def retrain(self) -> Dict[str, float]:
        """
        Retrain factor weights using logistic regression.

        Returns:
            New weights dict
        """
        if not self.should_retrain():
            return self.current_weights

        # Convert to feature matrix
        X, y = self._prepare_training_data()

        # Fit model
        self.model.fit(X, y)

        # Extract learned weights
        learned_weights = {}
        for i, factor in enumerate(sorted(self.current_weights.keys())):
            coef = self.model.coef_[0][i]
            # Normalize to [0, 1] range
            normalized_weight = 1 / (1 + np.exp(-coef))  # Sigmoid
            learned_weights[factor] = normalized_weight

        # Apply safety guardrails (limit weight changes)
        safe_weights = self._apply_guardrails(learned_weights)

        # Clear buffer after training
        self.training_buffer = []

        return safe_weights

    def _prepare_training_data(self):
        """Convert feedback buffer to sklearn format."""
        all_factors = sorted(self.current_weights.keys())
        X = []
        y = []

        for event_factors, label in self.training_buffer:
            # Create binary feature vector (1 if factor present, 0 otherwise)
            feature_vec = [1 if f in event_factors else 0 for f in all_factors]
            X.append(feature_vec)
            y.append(label)

        return np.array(X), np.array(y)

    def _apply_guardrails(self, new_weights: Dict[str, float]) -> Dict[str, float]:
        """
        Prevent drastic weight changes.

        Safety rules:
        1. Max 5% change per update
        2. Weights must stay in [0.01, 0.30] range
        3. Total weight sum must be <= 1.0
        """
        safe_weights = {}

        for factor, new_weight in new_weights.items():
            current = self.current_weights[factor]

            # Limit delta
            delta = new_weight - current
            if abs(delta) > self.max_weight_delta:
                delta = np.sign(delta) * self.max_weight_delta

            safe_weight = current + delta

            # Clamp to valid range
            safe_weight = max(0.01, min(0.30, safe_weight))
            safe_weights[factor] = safe_weight

        # Normalize to ensure sum <= 1.0
        total = sum(safe_weights.values())
        if total > 1.0:
            safe_weights = {k: v / total for k, v in safe_weights.items()}

        return safe_weights


# Integration point
async def periodic_weight_update_task():
    """Background task to retrain factor weights every 24 hours."""
    from src.artifact.factors import FACTOR_WEIGHTS
    from src.repositories.feedback_repo import FeedbackRepo
    from src.db.database import get_pool

    learner = FactorWeightLearner(FACTOR_WEIGHTS)
    pool = await get_pool()
    feedback_repo = FeedbackRepo(pool)

    while True:
        # Fetch recent feedback (last 24 hours)
        feedback_entries = await feedback_repo.get_recent_feedback(hours=24)

        for entry in feedback_entries:
            event_factors = entry['factors']
            label = 1 if entry['label'] == 'true_positive' else 0
            learner.add_feedback(event_factors, label)

        # Retrain if we have enough samples
        if learner.should_retrain():
            new_weights = learner.retrain()

            # Log weight changes
            print(f"[WeightLearner] Updated {len(new_weights)} factor weights")
            for factor, new_weight in new_weights.items():
                old_weight = FACTOR_WEIGHTS[factor]
                delta = new_weight - old_weight
                if abs(delta) > 0.01:  # Only log significant changes
                    print(f"  {factor}: {old_weight:.3f} → {new_weight:.3f} (Δ{delta:+.3f})")

            # Apply new weights (in A/B test mode first)
            await apply_weights_ab_test(new_weights, pool)

        # Sleep for 24 hours
        await asyncio.sleep(86400)
```

#### 3.2. Modify Feedback Endpoint to Trigger Learning
**File:** `src/api/feedback_endpoints.py` (MODIFY)

**Add after line 45:**

```python
from src.ml.factor_weight_learner import FactorWeightLearner

# Global learner instance (in production, use dependency injection)
_weight_learner = None

def get_weight_learner():
    global _weight_learner
    if _weight_learner is None:
        from src.artifact.factors import FACTOR_WEIGHTS
        _weight_learner = FactorWeightLearner(FACTOR_WEIGHTS)
    return _weight_learner


@router.post("/factor_vote")
async def factor_vote(
    event_id: str,
    factor: str,
    vote: int = Query(..., ge=-1, le=1),  # -1 FP, 0 neutral, +1 TP
    comment: Optional[str] = None,
    db: asyncpg.Pool = Depends(get_db_pool)
):
    """
    Analyst votes on factor relevance.

    This triggers online learning to adjust factor weights.
    """
    # Store vote in database
    feedback_repo = FeedbackRepo(db)
    await feedback_repo.record_factor_vote(event_id, factor, vote, comment)

    # Add to learner's buffer
    if vote != 0:  # Only learn from definitive votes
        learner = get_weight_learner()
        label = 1 if vote > 0 else 0

        # Fetch event factors from database
        event = await get_event_by_id(event_id, db)
        event_factors = event.get('factors', [])

        learner.add_feedback(event_factors, label)

        # Check if we should retrain
        if learner.should_retrain():
            new_weights = learner.retrain()
            # Store new weights for A/B testing
            await store_candidate_weights(new_weights, db)

            return {
                "status": "vote_recorded_and_retrained",
                "event_id": event_id,
                "factor": factor,
                "vote": vote,
                "new_weights_ready": True
            }

    return {
        "status": "vote_recorded",
        "event_id": event_id,
        "factor": factor,
        "vote": vote
    }
```

---

## 4. EMAIL DOMAIN ENHANCEMENT

### **Problem Statement:**
⚠️ Email security (60% complete - BEC basic, attachment analysis minimal)

### **Files to Create/Modify:**

#### 4.1. Email Attachment Analysis
**File:** `src/domains/email/attachment_analyzer.py` (NEW)

```python
"""
Email attachment analysis for malware/phishing detection.

Features:
1. Hash-based reputation (VirusTotal, etc.)
2. File type validation (detect mismatched extensions)
3. Macro detection in Office docs
4. Archive bomb detection (zip, tar)
5. Script file detection (vbs, js, ps1)
"""
import hashlib
import magic  # python-magic for file type detection
import re
from typing import Dict, List, Optional

class AttachmentAnalyzer:
    """Analyze email attachments for threats."""

    # Risky file extensions
    RISKY_EXTENSIONS = {
        'exe', 'dll', 'scr', 'bat', 'cmd', 'com', 'pif',  # Executables
        'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'ps1',  # Scripts
        'jar', 'app', 'deb', 'rpm',  # Packages
        'msi', 'msp',  # Installers
        'hta', 'cpl', 'inf', 'reg'  # System files
    }

    # Office docs with macro capability
    MACRO_CAPABLE = {'doc', 'docm', 'xls', 'xlsm', 'ppt', 'pptm'}

    def __init__(self, vt_api_key: Optional[str] = None):
        self.vt_api_key = vt_api_key
        self.file_magic = magic.Magic(mime=True)

    async def analyze(self, attachment: Dict) -> Dict:
        """
        Analyze attachment and return threat score.

        Args:
            attachment: {
                'filename': str,
                'content': bytes,
                'size': int
            }

        Returns:
            {
                'score': float (0-1),
                'factors': List[str],
                'recommendation': str
            }
        """
        filename = attachment['filename']
        content = attachment['content']
        size = attachment['size']

        score = 0.0
        factors = []

        # 1. Extension check
        ext = filename.split('.')[-1].lower()
        if ext in self.RISKY_EXTENSIONS:
            score += 0.30
            factors.append(f'email:attachment_risky_ext:{ext}')

        # 2. File type mismatch
        actual_type = self.file_magic.from_buffer(content)
        if self._is_extension_mismatch(filename, actual_type):
            score += 0.25
            factors.append('email:attachment_type_mismatch')

        # 3. Hash reputation (VirusTotal)
        file_hash = hashlib.sha256(content).hexdigest()
        vt_score = await self._check_virustotal(file_hash)
        if vt_score > 0.5:
            score += 0.40
            factors.append(f'email:attachment_vt_malicious:{vt_score:.2f}')

        # 4. Macro detection (Office docs)
        if ext in self.MACRO_CAPABLE:
            has_macro = self._detect_macro(content, ext)
            if has_macro:
                score += 0.20
                factors.append('email:attachment_has_macro')

        # 5. Archive bomb detection
        if ext in ('zip', 'tar', 'gz', 'bz2', 'rar'):
            compression_ratio = await self._check_archive_bomb(content)
            if compression_ratio > 100:  # 100x compression = suspicious
                score += 0.35
                factors.append(f'email:attachment_archive_bomb:{compression_ratio}x')

        # 6. Script content analysis
        if ext in ('vbs', 'js', 'ps1', 'bat'):
            script_score = self._analyze_script_content(content)
            score += script_score
            if script_score > 0.1:
                factors.append(f'email:attachment_malicious_script:{script_score:.2f}')

        # Recommendation
        if score >= 0.70:
            recommendation = "BLOCK: High-confidence malicious attachment"
        elif score >= 0.40:
            recommendation = "QUARANTINE: Suspicious attachment, manual review required"
        else:
            recommendation = "ALLOW: Low-risk attachment"

        return {
            'score': min(score, 1.0),
            'factors': factors,
            'recommendation': recommendation,
            'file_hash': file_hash,
            'file_type': actual_type
        }

    def _is_extension_mismatch(self, filename: str, mime_type: str) -> bool:
        """Detect file extension spoofing."""
        ext = filename.split('.')[-1].lower()

        # Expected MIME types for common extensions
        expected_mimes = {
            'pdf': 'application/pdf',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'jpg': 'image/jpeg',
            'png': 'image/png',
            'zip': 'application/zip',
        }

        expected = expected_mimes.get(ext)
        if expected and expected != mime_type:
            return True

        return False

    async def _check_virustotal(self, file_hash: str) -> float:
        """Query VirusTotal for file reputation."""
        if not self.vt_api_key:
            return 0.0  # No API key, skip check

        # TODO: Implement actual VT API call
        # For now, return mock score
        return 0.0

    def _detect_macro(self, content: bytes, ext: str) -> bool:
        """Detect macros in Office documents."""
        # Office Open XML documents with macros contain vbaProject.bin
        if b'vbaProject.bin' in content:
            return True

        # Legacy Office docs (.doc, .xls) have different structure
        if ext in ('doc', 'xls', 'ppt'):
            # Check for OLE signatures
            if content.startswith(b'\xd0\xcf\x11\xe0'):
                # Compound File Binary Format - may contain macros
                return b'Macros' in content or b'VBA' in content

        return False

    async def _check_archive_bomb(self, content: bytes) -> float:
        """Detect zip bombs by checking compression ratio."""
        import zipfile
        import io

        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                compressed_size = len(content)
                uncompressed_size = sum(info.file_size for info in zf.filelist)

                if compressed_size == 0:
                    return 0.0

                ratio = uncompressed_size / compressed_size
                return ratio
        except:
            return 0.0

    def _analyze_script_content(self, content: bytes) -> float:
        """Analyze script content for malicious patterns."""
        try:
            script_text = content.decode('utf-8', errors='ignore').lower()
        except:
            return 0.0

        score = 0.0

        # Suspicious PowerShell patterns
        ps_patterns = [
            r'invoke-expression',
            r'downloadstring',
            r'iex\s*\(',
            r'-encodedcommand',
            r'bypass.*executionpolicy',
            r'wscript\.shell',
        ]

        for pattern in ps_patterns:
            if re.search(pattern, script_text):
                score += 0.10

        # Obfuscation indicators
        if len(re.findall(r'[a-zA-Z]{50,}', script_text)) > 3:
            score += 0.15  # Long strings = potential obfuscation

        return min(score, 0.50)
```

#### 4.2. Integrate Attachment Analysis into Email Pipeline
**File:** `src/api/routes/email.py` (MODIFY - add after line 80)

```python
from src.domains.email.attachment_analyzer import AttachmentAnalyzer

@router.post("/ingest_with_attachments")
async def ingest_email_with_attachments(
    email: Dict,
    attachments: List[UploadFile] = File([]),
    db: asyncpg.Pool = Depends(get_db_pool)
):
    """
    Ingest email with attachment analysis.
    """
    analyzer = AttachmentAnalyzer(vt_api_key=os.getenv('VT_API_KEY'))

    email_factors = []
    attachment_results = []

    # Analyze each attachment
    for upload_file in attachments:
        content = await upload_file.read()

        attachment_data = {
            'filename': upload_file.filename,
            'content': content,
            'size': len(content)
        }

        result = await analyzer.analyze(attachment_data)
        attachment_results.append(result)

        # Add factors to email
        email_factors.extend(result['factors'])

    # Combine email factors with attachment factors
    email['factors'] = email.get('factors', []) + email_factors
    email['attachment_analysis'] = attachment_results

    # Route to correlation engine
    # ... (existing email ingestion logic)

    return {
        "status": "email_ingested",
        "attachment_count": len(attachments),
        "highest_attachment_score": max((r['score'] for r in attachment_results), default=0.0)
    }
```

---

## 5. IAM DOMAIN ENHANCEMENT

### **Problem Statement:**
⚠️ IAM analysis (65% - roles mapped, detection rules thin)

### **Files to Create:**

#### 5.1. Privilege Escalation Detection
**File:** `src/domains/iam/privilege_escalation.py` (NEW)

```python
"""
IAM privilege escalation detection.

Detects:
1. User assumes role with more permissions
2. Permission boundary bypass
3. Policy attachment to self
4. Adding user to admin group
5. Creating access keys for another user
"""
from typing import Dict, List
import networkx as nx  # For permission graph analysis

class PrivilegeEscalationDetector:
    """Detect IAM privilege escalation patterns."""

    def __init__(self):
        # Build permission hierarchy graph
        self.perm_graph = self._build_permission_graph()

    def detect(self, event: Dict) -> Dict:
        """
        Detect privilege escalation.

        Args:
            event: {
                'action': 'AssumeRole' | 'AttachUserPolicy' | 'AddUserToGroup' | ...,
                'principal': 'user:alice',
                'target_role': 'role:admin',
                'target_policy': 'policy:AdministratorAccess',
                'target_group': 'group:Admins',
                'timestamp': datetime
            }

        Returns:
            {
                'is_escalation': bool,
                'escalation_type': str,
                'score': float,
                'path': List[str]  # Escalation path
            }
        """
        action = event.get('action')
        principal = event.get('principal')

        if action == 'AssumeRole':
            return self._detect_role_assumption_escalation(event)
        elif action in ('AttachUserPolicy', 'PutUserPolicy'):
            return self._detect_policy_attachment_escalation(event)
        elif action == 'AddUserToGroup':
            return self._detect_group_escalation(event)
        elif action == 'CreateAccessKey':
            return self._detect_access_key_creation_escalation(event)

        return {'is_escalation': False, 'score': 0.0}

    def _detect_role_assumption_escalation(self, event: Dict) -> Dict:
        """
        Detect privilege escalation via AssumeRole.

        Escalation occurs if:
        - Target role has more permissions than current principal
        - Principal doesn't normally assume this role (anomaly)
        """
        principal = event['principal']
        target_role = event['target_role']

        # Get permission levels
        principal_level = self._get_permission_level(principal)
        target_level = self._get_permission_level(target_role)

        if target_level > principal_level:
            # This is an escalation
            score = (target_level - principal_level) / 10.0  # Normalize to 0-1

            # Check if this assumption is anomalous
            is_anomalous = self._is_anomalous_assumption(principal, target_role)
            if is_anomalous:
                score += 0.20

            return {
                'is_escalation': True,
                'escalation_type': 'role_assumption',
                'score': min(score, 1.0),
                'path': [principal, target_role],
                'principal_level': principal_level,
                'target_level': target_level
            }

        return {'is_escalation': False, 'score': 0.0}

    def _detect_policy_attachment_escalation(self, event: Dict) -> Dict:
        """Detect privilege escalation via policy attachment."""
        principal = event['principal']
        target_policy = event.get('target_policy', '')

        # Check if policy grants admin permissions
        is_admin_policy = any(admin_kw in target_policy.lower()
                              for admin_kw in ['administrator', 'poweruser', 'fullaccess'])

        if is_admin_policy:
            # Check if principal is attaching policy to self
            target_user = event.get('target_user', '')
            if principal == target_user:
                return {
                    'is_escalation': True,
                    'escalation_type': 'self_policy_attachment',
                    'score': 0.85,
                    'path': [principal, 'attached', target_policy]
                }

        return {'is_escalation': False, 'score': 0.0}

    def _detect_group_escalation(self, event: Dict) -> Dict:
        """Detect privilege escalation via group membership."""
        principal = event['principal']
        target_group = event.get('target_group', '')

        # Check if group has admin permissions
        is_admin_group = any(admin_kw in target_group.lower()
                             for admin_kw in ['admin', 'root', 'sudo'])

        if is_admin_group:
            # Check if principal added themselves
            target_user = event.get('target_user', '')
            if principal == target_user:
                return {
                    'is_escalation': True,
                    'escalation_type': 'self_group_addition',
                    'score': 0.90,
                    'path': [principal, 'added_to', target_group]
                }

        return {'is_escalation': False, 'score': 0.0}

    def _detect_access_key_creation_escalation(self, event: Dict) -> Dict:
        """Detect creation of access keys for privileged users."""
        principal = event['principal']
        target_user = event.get('target_user', '')

        # Creating access key for another user = potential credential theft
        if principal != target_user:
            target_level = self._get_permission_level(f"user:{target_user}")

            if target_level >= 8:  # Target is highly privileged
                return {
                    'is_escalation': True,
                    'escalation_type': 'access_key_creation_for_privileged_user',
                    'score': 0.75,
                    'path': [principal, 'created_key_for', target_user]
                }

        return {'is_escalation': False, 'score': 0.0}

    def _build_permission_graph(self) -> nx.DiGraph:
        """
        Build permission hierarchy graph.

        Levels (0-10):
        0: No permissions
        5: Read-only
        7: Power user
        10: Administrator
        """
        graph = nx.DiGraph()

        # Add nodes with permission levels
        graph.add_node('user:readonly', level=3)
        graph.add_node('user:developer', level=6)
        graph.add_node('user:poweruser', level=7)
        graph.add_node('user:admin', level=10)

        graph.add_node('role:ReadOnlyRole', level=4)
        graph.add_node('role:PowerUserRole', level=8)
        graph.add_node('role:AdministratorRole', level=10)

        return graph

    def _get_permission_level(self, entity: str) -> int:
        """Get permission level for an entity."""
        if entity in self.perm_graph:
            return self.perm_graph.nodes[entity]['level']

        # Default heuristic based on name
        entity_lower = entity.lower()
        if 'admin' in entity_lower or 'root' in entity_lower:
            return 10
        elif 'power' in entity_lower:
            return 7
        elif 'readonly' in entity_lower:
            return 3
        else:
            return 5  # Default

    def _is_anomalous_assumption(self, principal: str, role: str) -> bool:
        """Check if role assumption is anomalous (not seen before)."""
        # TODO: Query historical data to check if principal has assumed this role before
        # For now, return False (assume all assumptions are normal)
        return False
```

---

## 6. CLOUD DOMAIN ENHANCEMENT

### **Problem Statement:**
⚠️ Cloud connectors (70% - CloudTrail parsing works, adapter integration limited)

### **Files to Create:**

#### 6.1. AWS CloudTrail Event Parser Enhancement
**File:** `src/domains/cloud/aws_cloudtrail_parser.py` (MODIFY existing or CREATE)

**Add support for 20+ high-risk CloudTrail events:**

```python
"""
Enhanced AWS CloudTrail event parser.

High-risk events:
1. CreateAccessKey (credential theft)
2. PutBucketPolicy (public bucket exposure)
3. ModifyInstanceAttribute (instance metadata access)
4. AuthorizeSecurityGroupIngress (firewall rule change)
5. CreateDBSnapshot (data exfiltration)
... (15 more)
"""

# High-risk CloudTrail events with scoring
HIGH_RISK_EVENTS = {
    'CreateAccessKey': {'score': 0.35, 'mitre': 'T1098'},
    'DeleteAccessKey': {'score': 0.25, 'mitre': 'T1531'},
    'PutBucketPolicy': {'score': 0.40, 'mitre': 'T1530'},
    'PutBucketAcl': {'score': 0.40, 'mitre': 'T1530'},
    'ModifyInstanceAttribute': {'score': 0.35, 'mitre': 'T1525'},
    'AuthorizeSecurityGroupIngress': {'score': 0.30, 'mitre': 'T1562.007'},
    'CreateDBSnapshot': {'score': 0.25, 'mitre': 'T1530'},
    'ModifyDBInstance': {'score': 0.30, 'mitre': 'T1565'},
    'PutUserPolicy': {'score': 0.45, 'mitre': 'T1098'},
    'AttachUserPolicy': {'score': 0.45, 'mitre': 'T1098'},
    'CreateUser': {'score': 0.20, 'mitre': 'T1136'},
    'DeleteTrail': {'score': 0.50, 'mitre': 'T1562.008'},  # CRITICAL
    'StopLogging': {'score': 0.50, 'mitre': 'T1562.008'},  # CRITICAL
    'PutEventSelectors': {'score': 0.40, 'mitre': 'T1562.008'},
    'ConsoleLogin': {'score': 0.10, 'mitre': 'T1078'},
    'AssumeRole': {'score': 0.15, 'mitre': 'T1078'},
    'GetSecretValue': {'score': 0.25, 'mitre': 'T1555'},
    'PutSecretValue': {'score': 0.30, 'mitre': 'T1552'},
    'ModifyVpcAttribute': {'score': 0.30, 'mitre': 'T1562'},
    'CreateSnapshot': {'score': 0.20, 'mitre': 'T1530'},
}

def parse_cloudtrail_event(event: Dict) -> Dict:
    """
    Parse CloudTrail event and extract security factors.

    Returns:
        {
            'event_name': str,
            'principal': str,
            'resource': str,
            'source_ip': str,
            'factors': List[str],
            'score': float,
            'mitre': List[str]
        }
    """
    event_name = event.get('eventName')
    principal_arn = event.get('userIdentity', {}).get('arn', '')
    source_ip = event.get('sourceIPAddress', '')
    request_params = event.get('requestParameters', {})

    factors = []
    score = 0.0
    mitre_tactics = []

    # Base detection: high-risk event
    if event_name in HIGH_RISK_EVENTS:
        risk_data = HIGH_RISK_EVENTS[event_name]
        score += risk_data['score']
        factors.append(f'cloud:high_risk_event:{event_name}')
        mitre_tactics.append(risk_data['mitre'])

    # Context-based scoring

    # 1. Public bucket exposure
    if event_name in ('PutBucketPolicy', 'PutBucketAcl'):
        policy = request_params.get('bucketPolicy', {})
        if is_public_policy(policy):
            score += 0.35
            factors.append('cloud:public_bucket_exposure')

    # 2. Security group 0.0.0.0/0 exposure
    if event_name == 'AuthorizeSecurityGroupIngress':
        ip_ranges = request_params.get('ipPermissions', [])
        if any('0.0.0.0/0' in str(ip_range) for ip_range in ip_ranges):
            score += 0.25
            factors.append('cloud:sg_world_accessible')

    # 3. Root account usage (should never happen)
    if 'root' in principal_arn:
        score += 0.40
        factors.append('cloud:root_account_usage')

    # 4. Unusual source IP (geographic anomaly)
    if is_unusual_source_ip(source_ip, principal_arn):
        score += 0.20
        factors.append('cloud:unusual_source_ip')

    # 5. Failed authentication (brute force indicator)
    if event.get('errorCode') in ('UnauthorizedOperation', 'AccessDenied'):
        score += 0.10
        factors.append('cloud:failed_auth')

    return {
        'event_name': event_name,
        'principal': principal_arn,
        'source_ip': source_ip,
        'factors': factors,
        'score': min(score, 1.0),
        'mitre': mitre_tactics
    }


def is_public_policy(policy: Dict) -> bool:
    """Check if S3 bucket policy allows public access."""
    statements = policy.get('Statement', [])

    for stmt in statements:
        if stmt.get('Effect') == 'Allow':
            principal = stmt.get('Principal', '')
            if principal == '*' or principal.get('AWS') == '*':
                return True

    return False


def is_unusual_source_ip(source_ip: str, principal: str) -> bool:
    """Check if source IP is unusual for this principal."""
    # TODO: Query historical data for this principal's typical IPs
    # For now, check if IP is from high-risk country
    HIGH_RISK_COUNTRIES = ['CN', 'RU', 'KP', 'IR']

    # Use GeoIP lookup (requires geoip2 library)
    # country = geoip_lookup(source_ip)
    # return country in HIGH_RISK_COUNTRIES

    return False  # Placeholder
```

---

## 7. THREAT INTEL INTEGRATION

### **Problem Statement:**
- Threat intel feeds incomplete (MISP/OpenCTI placeholders ~50% complete)
- No real-time threat feed ingestion
- No IOC matching against events

### **Files to Create:**

#### 7.1. MISP Integration
**File:** `src/integrations/threat_intel/misp_client.py` (NEW)

```python
"""
MISP (Malware Information Sharing Platform) integration.

Features:
1. Fetch IOCs (IP, domain, hash, email)
2. Match IOCs against incoming events
3. Enrich events with threat context
"""
import aiohttp
from typing import List, Dict
from datetime import datetime, timedelta

class MISPClient:
    """Client for MISP threat intel platform."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            'Authorization': api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        self.ioc_cache = {}  # Cache IOCs for 1 hour
        self.cache_ttl = 3600

    async def fetch_recent_iocs(self, hours: int = 24) -> Dict[str, List[str]]:
        """
        Fetch IOCs published in last N hours.

        Returns:
            {
                'ip': ['1.2.3.4', '5.6.7.8'],
                'domain': ['evil.com', 'malware.net'],
                'hash': ['abc123...', 'def456...'],
                'email': ['attacker@evil.com']
            }
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)

        async with aiohttp.ClientSession() as session:
            # Query MISP events
            url = f"{self.base_url}/events/restSearch"
            payload = {
                'returnFormat': 'json',
                'published': 1,
                'timestamp': cutoff_time.timestamp(),
                'limit': 1000
            }

            async with session.post(url, json=payload, headers=self.headers) as resp:
                if resp.status != 200:
                    raise Exception(f"MISP API error: {resp.status}")

                data = await resp.json()

        # Parse events and extract IOCs
        iocs = {'ip': [], 'domain': [], 'hash': [], 'email': []}

        for event in data.get('response', []):
            for attribute in event.get('Event', {}).get('Attribute', []):
                ioc_type = attribute.get('type')
                ioc_value = attribute.get('value')

                if ioc_type in ('ip-src', 'ip-dst'):
                    iocs['ip'].append(ioc_value)
                elif ioc_type == 'domain':
                    iocs['domain'].append(ioc_value)
                elif ioc_type in ('md5', 'sha1', 'sha256'):
                    iocs['hash'].append(ioc_value)
                elif ioc_type == 'email-src':
                    iocs['email'].append(ioc_value)

        # Cache IOCs
        self.ioc_cache = iocs
        self.ioc_cache['timestamp'] = datetime.utcnow().timestamp()

        return iocs

    async def match_event(self, event: Dict) -> Dict:
        """
        Match event against MISP IOCs.

        Args:
            event: {
                'ip': '1.2.3.4',
                'domain': 'example.com',
                'hash': 'abc123...',
                'email': 'sender@example.com'
            }

        Returns:
            {
                'matched': bool,
                'ioc_type': 'ip' | 'domain' | 'hash' | 'email',
                'ioc_value': str,
                'threat_score': float
            }
        """
        # Refresh cache if stale
        if not self.ioc_cache or (datetime.utcnow().timestamp() - self.ioc_cache.get('timestamp', 0)) > self.cache_ttl:
            await self.fetch_recent_iocs()

        # Check for matches
        event_ip = event.get('ip')
        event_domain = event.get('domain')
        event_hash = event.get('hash')
        event_email = event.get('email')

        if event_ip and event_ip in self.ioc_cache.get('ip', []):
            return {'matched': True, 'ioc_type': 'ip', 'ioc_value': event_ip, 'threat_score': 0.80}

        if event_domain and event_domain in self.ioc_cache.get('domain', []):
            return {'matched': True, 'ioc_type': 'domain', 'ioc_value': event_domain, 'threat_score': 0.85}

        if event_hash and event_hash in self.ioc_cache.get('hash', []):
            return {'matched': True, 'ioc_type': 'hash', 'ioc_value': event_hash, 'threat_score': 0.95}

        if event_email and event_email in self.ioc_cache.get('email', []):
            return {'matched': True, 'ioc_type': 'email', 'ioc_value': event_email, 'threat_score': 0.75}

        return {'matched': False, 'threat_score': 0.0}
```

#### 7.2. Integrate MISP into Event Pipeline
**File:** `src/core/event_pipeline/stages/threat_intel.py` (NEW)

```python
"""
Threat intel enrichment stage.

Matches events against:
1. MISP IOCs
2. AlienVault OTX
3. Abuse.ch feeds
"""
from src.integrations.threat_intel.misp_client import MISPClient
import os

class ThreatIntelStage:
    """Enrich events with threat intelligence."""

    def __init__(self):
        misp_url = os.getenv('MISP_URL')
        misp_key = os.getenv('MISP_API_KEY')

        self.misp_client = MISPClient(misp_url, misp_key) if misp_url and misp_key else None

    async def process(self, event: Dict) -> Dict:
        """
        Enrich event with threat intel.

        Adds factors:
        - threat_intel:misp_match:ip
        - threat_intel:misp_match:domain
        - threat_intel:misp_match:hash
        """
        if not self.misp_client:
            return event  # No MISP configured, skip

        # Extract IOC fields from event
        ioc_event = {
            'ip': event.get('dst_ip') or event.get('ip'),
            'domain': event.get('domain'),
            'hash': event.get('file_hash'),
            'email': event.get('from_email')
        }

        # Match against MISP
        match_result = await self.misp_client.match_event(ioc_event)

        if match_result['matched']:
            # Add threat intel factor
            factor = f"threat_intel:misp_match:{match_result['ioc_type']}"
            event.setdefault('factors', []).append(factor)

            # Boost confidence
            event['confidence'] = event.get('confidence', 0.0) + match_result['threat_score']

            # Add context
            event.setdefault('enrichment', {})['misp'] = match_result

        return event
```

#### 7.3. Register Threat Intel Stage in Pipeline
**File:** `src/core/event_pipeline/stages/__init__.py` (MODIFY - add after line 40)

```python
from src.core.event_pipeline.stages.threat_intel import ThreatIntelStage

# Add to PIPELINE_STAGES list
PIPELINE_STAGES = [
    # ... existing stages
    ('threat_intel', ThreatIntelStage(), {'heavy': False}),  # Add before correlation
    # ... remaining stages
]
```

---

## 8. HORIZONTAL SCALING & HIGH AVAILABILITY

### **Problem Statement:**
- Single-node architecture (bottleneck at 1k events/sec)
- No distributed graph database
- Redis single-instance (not clustered)

### **Files to Create/Modify:**

#### 8.1. Distributed HopGraph with Redis Cluster
**File:** `src/graph/distributed_hopgraph.py` (NEW)

```python
"""
Distributed HopGraph using Redis Cluster for horizontal scaling.

Architecture:
- Graph nodes/edges stored in Redis hashes
- Partitioned by node ID (consistent hashing)
- Support for multi-node Redis Cluster
"""
import redis
from redis.cluster import RedisCluster
import hashlib
import json
from typing import List, Dict

class DistributedHopGraph:
    """Distributed graph backend using Redis Cluster."""

    def __init__(self, redis_nodes: List[Dict]):
        """
        Args:
            redis_nodes: [
                {'host': 'redis1', 'port': 6379},
                {'host': 'redis2', 'port': 6379},
                {'host': 'redis3', 'port': 6379}
            ]
        """
        self.cluster = RedisCluster(
            startup_nodes=redis_nodes,
            decode_responses=True,
            skip_full_coverage_check=False
        )

    def add_node(self, node_id: str, node_type: str, properties: Dict):
        """Add node to distributed graph."""
        node_key = f"node:{node_id}"
        node_data = {
            'id': node_id,
            'type': node_type,
            **properties
        }

        # Store node in Redis
        self.cluster.hset(node_key, mapping=node_data)

        # Add to type index
        self.cluster.sadd(f"nodes:type:{node_type}", node_id)

    def add_edge(self, src: str, dst: str, etype: str, properties: Dict):
        """Add edge to distributed graph."""
        edge_id = f"{src}|{dst}|{etype}"
        edge_key = f"edge:{edge_id}"

        edge_data = {
            'src': src,
            'dst': dst,
            'type': etype,
            **properties
        }

        # Store edge
        self.cluster.hset(edge_key, mapping=edge_data)

        # Add to src/dst adjacency lists
        self.cluster.sadd(f"edges:src:{src}", edge_id)
        self.cluster.sadd(f"edges:dst:{dst}", edge_id)

    def get_neighbors(self, node_id: str) -> List[str]:
        """Get all neighbors of a node."""
        edge_ids = self.cluster.smembers(f"edges:src:{node_id}")

        neighbors = []
        for edge_id in edge_ids:
            edge_data = self.cluster.hgetall(f"edge:{edge_id}")
            neighbors.append(edge_data['dst'])

        return neighbors

    def bfs_search(self, start_node: str, max_depth: int = 3) -> List[List[str]]:
        """BFS search for attack paths."""
        paths = []
        queue = [([start_node], 0)]  # (path, depth)
        visited = set()

        while queue:
            path, depth = queue.pop(0)
            current = path[-1]

            if current in visited:
                continue
            visited.add(current)

            if depth >= max_depth:
                paths.append(path)
                continue

            neighbors = self.get_neighbors(current)
            for neighbor in neighbors:
                new_path = path + [neighbor]
                queue.append((new_path, depth + 1))

        return paths
```

#### 8.2. Kubernetes StatefulSet for PostgreSQL
**File:** `deploy/kubernetes/postgres-statefulset.yaml` (NEW)

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: janusec
spec:
  serviceName: postgres
  replicas: 3  # Primary + 2 read replicas
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:14
        env:
        - name: POSTGRES_DB
          value: janusec
        - name: POSTGRES_USER
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: username
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: password
        - name: PGDATA
          value: /var/lib/postgresql/data/pgdata
        ports:
        - containerPort: 5432
          name: postgres
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
        livenessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - janusec
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - janusec
          initialDelaySeconds: 5
          periodSeconds: 5
  volumeClaimTemplates:
  - metadata:
      name: postgres-storage
    spec:
      accessModes: [ "ReadWriteOnce" ]
      storageClassName: "standard"
      resources:
        requests:
          storage: 100Gi
---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: janusec
spec:
  clusterIP: None  # Headless service for StatefulSet
  selector:
    app: postgres
  ports:
  - port: 5432
    name: postgres
---
# Read-only service for replicas
apiVersion: v1
kind: Service
metadata:
  name: postgres-read
  namespace: janusec
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    name: postgres
```

#### 8.3. Redis Cluster Deployment
**File:** `deploy/kubernetes/redis-cluster.yaml` (NEW)

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis-cluster
  namespace: janusec
spec:
  serviceName: redis-cluster
  replicas: 6  # 3 masters + 3 replicas
  selector:
    matchLabels:
      app: redis-cluster
  template:
    metadata:
      labels:
        app: redis-cluster
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        command:
          - "redis-server"
          - "--cluster-enabled"
          - "yes"
          - "--cluster-config-file"
          - "/data/nodes.conf"
          - "--cluster-node-timeout"
          - "5000"
          - "--appendonly"
          - "yes"
        ports:
        - containerPort: 6379
          name: client
        - containerPort: 16379
          name: gossip
        volumeMounts:
        - name: redis-data
          mountPath: /data
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
  volumeClaimTemplates:
  - metadata:
      name: redis-data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 10Gi
---
apiVersion: v1
kind: Service
metadata:
  name: redis-cluster
  namespace: janusec
spec:
  clusterIP: None
  selector:
    app: redis-cluster
  ports:
  - port: 6379
    name: client
  - port: 16379
    name: gossip
```

---

## 9. SECURITY HARDENING

### **Problem Statement:**
- No OWASP Top 10 testing
- SQL/NoSQL injection testing needed
- XSS/CSRF in frontend

### **Security Checklist:**

#### 9.1. Input Validation Enhancement
**File:** `src/api/security/input_validator.py` (NEW)

```python
"""
Input validation for all API endpoints.

Validates:
1. SQL injection patterns
2. NoSQL injection patterns
3. XSS payloads
4. Path traversal
5. Command injection
"""
import re
from fastapi import HTTPException

class InputValidator:
    """Validate user inputs for security threats."""

    SQL_INJECTION_PATTERNS = [
        r"(\bUNION\b.*\bSELECT\b)",
        r"(\bDROP\b.*\bTABLE\b)",
        r"(\bINSERT\b.*\bINTO\b)",
        r"(--|;|\/\*|\*\/)",
        r"(\bOR\b\s+\d+=\d+)",
        r"(\'\s+OR\s+\'1\'=\'1)",
    ]

    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"<iframe",
    ]

    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e/",
        r"%2e%2e\\",
    ]

    def validate_string(self, value: str, field_name: str):
        """Validate string input for common attacks."""
        if not value:
            return

        # SQL injection check
        for pattern in self.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid input in '{field_name}': potential SQL injection"
                )

        # XSS check
        for pattern in self.XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid input in '{field_name}': potential XSS payload"
                )

        # Path traversal check
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, value):
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid input in '{field_name}': potential path traversal"
                )

    def sanitize_filename(self, filename: str) -> str:
        """Sanitize uploaded file names."""
        # Remove path components
        filename = filename.replace('/', '_').replace('\\', '_')

        # Remove null bytes
        filename = filename.replace('\x00', '')

        # Limit length
        if len(filename) > 255:
            filename = filename[:255]

        return filename
```

**Apply to all endpoints:**
**File:** `src/api/dependencies.py` (ADD)

```python
from src.api.security.input_validator import InputValidator

def get_input_validator():
    """Dependency for input validation."""
    return InputValidator()

# Use in endpoints:
# @router.post("/some_endpoint")
# async def some_endpoint(
#     user_input: str,
#     validator: InputValidator = Depends(get_input_validator)
# ):
#     validator.validate_string(user_input, "user_input")
#     ...
```

---

## 10. TESTING INFRASTRUCTURE

### **Problem Statement:**
- Load testing at 10k events/sec needed
- Chaos engineering tests missing
- E2E integration tests partial

### **Files to Create:**

#### 10.1. Load Testing Suite
**File:** `tests/load/locustfile.py` (NEW)

```python
"""
Locust load testing for JanuSec platform.

Tests:
1. Event ingestion throughput (target: 10k events/sec)
2. Decision API latency (target: p95 < 10s)
3. HopGraph query performance (target: p95 < 1s)
"""
from locust import HttpUser, task, between
import json
import random

class JanuSecUser(HttpUser):
    wait_time = between(0.1, 0.5)

    @task(10)  # Weight: 10
    def ingest_event(self):
        """Simulate event ingestion."""
        event = {
            "tenant_id": "load_test",
            "timestamp": "2025-01-15T10:00:00Z",
            "host": f"host-{random.randint(1, 100)}",
            "process_name": random.choice(['powershell.exe', 'cmd.exe', 'python.exe']),
            "command_line": "test command",
            "dst_ip": f"192.168.1.{random.randint(1, 254)}"
        }

        self.client.post("/api/v1/ingest/generic", json=event)

    @task(5)  # Weight: 5
    def query_decisions(self):
        """Simulate decision API queries."""
        self.client.get("/api/v1/decisions", params={"tenant_id": "load_test", "limit": 10})

    @task(2)  # Weight: 2
    def hopgraph_query(self):
        """Simulate HopGraph explain queries."""
        self.client.post("/api/v1/graph/explain", json={
            "start_node": f"host:host-{random.randint(1, 100)}",
            "max_hops": 3
        })
```

**Run load test:**
```bash
locust -f tests/load/locustfile.py --host=http://localhost:8080 --users=1000 --spawn-rate=100 --run-time=1h
```

---

## IMPLEMENTATION PRIORITY MATRIX

| Priority | Component | Effort (weeks) | Impact | Files |
|---|---|---|---|---|
| **P0 (Critical)** | Production Metrics & Dashboards | 2-3 | HIGH | `src/repositories/precision_metrics_repo.py`, `src/api/metrics_status_endpoints.py` |
| **P0** | Correlation Rules (Week1 enhancement) | 3-4 | HIGH | `src/core/correlation/rules/week1/*.py` |
| **P0** | Closed-Loop Learning | 4-6 | HIGH | `src/ml/factor_weight_learner.py`, `src/api/feedback_endpoints.py` |
| **P1 (High)** | Email Attachment Analysis | 2-3 | MEDIUM | `src/domains/email/attachment_analyzer.py` |
| **P1** | IAM Privilege Escalation | 2-3 | MEDIUM | `src/domains/iam/privilege_escalation.py` |
| **P1** | Cloud Domain Enhancement | 2-3 | MEDIUM | `src/domains/cloud/aws_cloudtrail_parser.py` |
| **P2 (Medium)** | Threat Intel Integration (MISP) | 3-4 | MEDIUM | `src/integrations/threat_intel/misp_client.py` |
| **P2** | Security Hardening | 2-3 | HIGH | `src/api/security/input_validator.py` |
| **P2** | Load Testing | 1-2 | HIGH | `tests/load/locustfile.py` |
| **P3 (Low)** | Distributed HopGraph | 6-8 | LOW | `src/graph/distributed_hopgraph.py` |
| **P3** | Kubernetes HA | 4-6 | LOW | `deploy/kubernetes/*.yaml` |

---

## ESTIMATED TIMELINE

**With 2-3 Engineers:**

- **Month 1:** P0 items (Production metrics, Correlation rules, Closed-loop learning)
- **Month 2:** P1 items (Email, IAM, Cloud enhancements)
- **Month 3:** P2 items (Threat intel, Security hardening, Load testing)
- **Months 4-6:** P3 items (Distributed architecture, Kubernetes HA)

**Total: 6 months to production-ready state**

---

This roadmap provides specific, actionable implementation guidance with exact file locations and code samples. Let me know if you need deeper dives into any specific component!
