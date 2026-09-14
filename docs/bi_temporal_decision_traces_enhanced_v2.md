# Bi-Temporal Decision Traces for JanuSec Context Graph
## Enhanced Architecture Specification v2.0

This document provides a comprehensive approach to integrating bi-temporal decision traces into JanuSec's context graph architecture. It incorporates industry-validated patterns from production deployments at Netflix, Microsoft, Zep/Graphiti, and emerging compliance requirements from ISO 42001, NIST AI RMF, and EU AI Act.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Why Bi-Temporal Decision Traces](#why-bi-temporal-decision-traces)
3. [Core Trace Schema (Property Graph)](#core-trace-schema-property-graph)
4. [Cypher Schema Definitions](#cypher-schema-definitions)
5. [ExplanationCache Pattern](#explanationcache-pattern)
6. [Ingestion Anomaly Detection](#ingestion-anomaly-detection)
7. [Context Graph Integration Architecture](#context-graph-integration-architecture)
8. [Performance Envelope & SLOs](#performance-envelope--slos)
9. [Pipeline Integration Points](#pipeline-integration-points)
10. [Multi-Source Correlation Enhancement](#multi-source-correlation-enhancement)
11. [Tiered LLM Summaries](#tiered-llm-summaries)
12. [Cyber Risk Quantification](#cyber-risk-quantification)
13. [Compliance Framework Mapping](#compliance-framework-mapping)
14. [API Specifications](#api-specifications)
15. [Security Considerations](#security-considerations)
16. [Implementation Phases](#implementation-phases)
17. [Acceptance Criteria](#acceptance-criteria)

---

## Executive Summary

JanuSec's context graph architecture extends beyond traditional knowledge graphs by capturing **decision traces**—the complete record of inputs, policy evaluations, exceptions, and outcomes that enable AI-driven security triage. This specification introduces bi-temporal modeling to provide:

- **Audit-ready explainability** for EU AI Act Article 12 compliance (August 2026 deadline)
- **Point-in-time reconstruction** for incident investigation and regulatory response
- **Ingestion gap detection** through novel bi-temporal delta analysis
- **Pre-computed explanation paths** for sub-200ms analyst triage responses

The architecture aligns with production patterns from Zep/Graphiti (94.8% memory retrieval accuracy), Microsoft GraphRAG (70-80% improvement over vector RAG), and Netflix's real-time distributed graph (billions of events daily).

**Key Differentiator:** The missing logs detection via bi-temporal delta analysis is a novel application not documented in current industry literature, directly addressing SOC blind-spot quantification.

---

## Why Bi-Temporal Decision Traces

### The Compliance Imperative

| Regulation | Requirement | Bi-Temporal Solution |
|------------|-------------|---------------------|
| **EU AI Act Art. 12** | Automatic logging enabling traceability | Four-timestamp model reconstructs decision state |
| **EU AI Act Art. 14** | Human oversight capability | `as_of` queries enable historical replay |
| **ISO 42001 A.6.2.6** | AI system documentation | Graph schema serves as living documentation |
| **ISO 27001 A.8.15** | Event logging | Audit schema with traversal paths |
| **NIST AI RMF MAP 1.1** | Intended purpose documentation | `intended_purpose` field on Decision nodes |

### The Four-Timestamp Model

Every trace artifact carries four temporal markers:

```
┌─────────────────────────────────────────────────────────────────┐
│                    BI-TEMPORAL TIMELINE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Real World    ──●────────────────●──────────────────────────▶  │
│  (Valid Time)    t_valid          t_invalid                     │
│                  │                │                             │
│                  │ Event          │ Event no longer             │
│                  │ occurred       │ true/relevant               │
│                                                                 │
│  System         ────────●────────────────●───────────────────▶  │
│  (Transaction)          t_created        t_expired              │
│                         │                │                      │
│                         │ Ingested       │ Superseded/          │
│                         │ into system    │ archived             │
│                                                                 │
│  DELTA = t_created - t_valid  ← Ingestion latency indicator    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Critical Insight:** The delta between `t_valid` and `t_created` reveals:
- **Positive delta:** Normal ingestion latency (expected: seconds to minutes)
- **Large positive delta:** Delayed telemetry (blind spot risk)
- **Negative delta:** Future-dated events (clock skew or replay attack)
- **Missing expected events:** Ingestion failure (gap detection)

---

## Core Trace Schema (Property Graph)

### Entity Definitions

```
┌─────────────────────────────────────────────────────────────────┐
│                    DECISION TRACE GRAPH                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐    CONTAINS    ┌──────────┐                      │
│  │ Session  │───────────────▶│ Decision │                      │
│  └──────────┘                └────┬─────┘                      │
│                                   │                             │
│            ┌──────────────────────┼──────────────────────┐     │
│            │                      │                      │     │
│            ▼                      ▼                      ▼     │
│     ┌──────────┐          ┌────────────┐          ┌──────────┐ │
│     │ Evidence │          │ PolicyEval │          │ Outcome  │ │
│     └────┬─────┘          └─────┬──────┘          └──────────┘ │
│          │                      │                              │
│          ▼                      ▼                              │
│  ┌───────────────┐      ┌─────────────┐                       │
│  │ Domain Entity │      │  Exception  │                       │
│  │ (Identity,    │      └─────────────┘                       │
│  │  Device, IP,  │                                            │
│  │  Host, etc.)  │      ┌─────────────┐                       │
│  └───────────────┘      │  Precedent  │◀── REFERENCES_PRECEDENT│
│                         └─────────────┘                       │
│                                                                │
│  ┌──────────────────┐                                         │
│  │ExplanationCache  │◀── EXPLAINED_BY (pre-computed paths)    │
│  └──────────────────┘                                         │
│                                                                │
└─────────────────────────────────────────────────────────────────┘
```

### Node Types

| Node Type | Purpose | Key Properties |
|-----------|---------|----------------|
| `Session` | Multi-source correlation container | `session_id`, `created_at`, `status`, `domain_coverage` |
| `Decision` | Discrete correlation/verdict event | `decision_id`, `decision_type`, `confidence`, `intended_purpose`, `deployment_context` |
| `Evidence` | Normalized inputs with provenance | `evidence_id`, `source_system`, `connector`, `fields_present`, `high_value_fields_count` |
| `PolicyEval` | Rules and scores evaluated | `policy_id`, `policy_version`, `scoring_config_version`, `explainable_factors` |
| `Exception` | Overrides or special handling | `exception_id`, `exception_type`, `justification`, `approved_by` |
| `Outcome` | Actionable results | `outcome_id`, `action_type`, `severity`, `recommendations` |
| `Precedent` | Prior similar decisions | `precedent_id`, `similarity_score`, `decision_ref` |
| `ExplanationCache` | Pre-computed human-readable paths | `explanation_id`, `natural_language`, `path_nodes`, `generated_at` |

### Domain Entity Nodes

| Node Type | Identity Fields | Stitching Keys |
|-----------|-----------------|----------------|
| `Identity` | `user`, `upn`, `sid`, `email`, `employee_id` | `canonical_id`, `aliases` |
| `Device` | `hostname`, `device_id`, `mac_address`, `serial` | `canonical_id`, `os_fingerprint` |
| `Host` | `fqdn`, `ip_addresses`, `cloud_instance_id` | `canonical_id`, `environment` |
| `Process` | `process_name`, `pid`, `command_line`, `hash` | `parent_process_id` |
| `FileHash` | `sha256`, `sha1`, `md5`, `file_path` | `first_seen`, `prevalence` |
| `Domain` | `domain_name`, `registrar`, `creation_date` | `threat_intel_tags` |
| `IP` | `ip_address`, `asn`, `geo_location`, `ptr_record` | `reputation_score` |
| `CloudResource` | `resource_id`, `arn`, `resource_type`, `region` | `account_id`, `tags` |

---

## Cypher Schema Definitions

### Constraint and Index Creation

```cypher
// ============================================================
// CONSTRAINTS - Ensure data integrity
// ============================================================

// Primary key constraints
CREATE CONSTRAINT session_id_unique IF NOT EXISTS
FOR (s:Session) REQUIRE s.session_id IS UNIQUE;

CREATE CONSTRAINT decision_id_unique IF NOT EXISTS
FOR (d:Decision) REQUIRE d.decision_id IS UNIQUE;

CREATE CONSTRAINT evidence_id_unique IF NOT EXISTS
FOR (e:Evidence) REQUIRE e.evidence_id IS UNIQUE;

CREATE CONSTRAINT policy_eval_id_unique IF NOT EXISTS
FOR (p:PolicyEval) REQUIRE p.policy_eval_id IS UNIQUE;

CREATE CONSTRAINT explanation_id_unique IF NOT EXISTS
FOR (x:ExplanationCache) REQUIRE x.explanation_id IS UNIQUE;

// Identity stitching constraints
CREATE CONSTRAINT identity_canonical_unique IF NOT EXISTS
FOR (i:Identity) REQUIRE i.canonical_id IS UNIQUE;

CREATE CONSTRAINT device_canonical_unique IF NOT EXISTS
FOR (d:Device) REQUIRE d.canonical_id IS UNIQUE;

// ============================================================
// INDEXES - Optimize query performance
// ============================================================

// Bi-temporal indexes (critical for as_of queries)
CREATE INDEX evidence_t_valid IF NOT EXISTS
FOR (e:Evidence) ON (e.t_valid);

CREATE INDEX evidence_t_created IF NOT EXISTS
FOR (e:Evidence) ON (e.t_created);

CREATE INDEX decision_t_valid IF NOT EXISTS
FOR (d:Decision) ON (d.t_valid);

// Composite index for time-range queries
CREATE INDEX evidence_temporal_range IF NOT EXISTS
FOR (e:Evidence) ON (e.t_valid, e.t_invalid, e.t_created);

// Source system indexes for ingestion analysis
CREATE INDEX evidence_source IF NOT EXISTS
FOR (e:Evidence) ON (e.source_system, e.connector);

// Full-text search for explanation queries
CREATE FULLTEXT INDEX explanation_text IF NOT EXISTS
FOR (x:ExplanationCache) ON EACH [x.natural_language];

// Vector index for semantic similarity (Neo4j 5.11+)
CREATE VECTOR INDEX decision_embedding IF NOT EXISTS
FOR (d:Decision) ON (d.embedding)
OPTIONS {indexConfig: {
  `vector.dimensions`: 1536,
  `vector.similarity_function`: 'cosine'
}};
```

### Node Creation Templates

```cypher
// ============================================================
// SESSION NODE
// ============================================================
CREATE (s:Session {
  session_id: $session_id,
  created_at: datetime(),
  status: 'active',
  domain_coverage: $domains,  // ['endpoint', 'identity', 'network', 'cloud']
  correlation_window_start: $window_start,
  correlation_window_end: $window_end,
  
  // Bi-temporal
  t_valid: $window_start,
  t_invalid: null,  // Set when session closes
  t_created: datetime(),
  t_expired: null,
  
  // Governance
  scoring_config_version: $scoring_version,
  pipeline_version: $pipeline_version
})

// ============================================================
// DECISION NODE
// ============================================================
CREATE (d:Decision {
  decision_id: $decision_id,
  session_id: $session_id,
  decision_type: $type,  // 'correlation' | 'verdict' | 'escalation'
  confidence: $confidence,
  severity: $severity,
  
  // NIST AI RMF compliance fields
  intended_purpose: $purpose,  // 'security_triage' | 'incident_escalation' | 'compliance_audit'
  deployment_context: $context,  // Maps to NIST deployment documentation
  
  // Bi-temporal
  t_valid: $event_time,
  t_invalid: null,
  t_created: datetime(),
  t_expired: null,
  
  // Explainability
  explainable_factors: $factors,  // JSON array of contributing factors
  factor_weights: $weights,
  
  // Embedding for precedent matching (populated async)
  embedding: null
})

// ============================================================
// EVIDENCE NODE
// ============================================================
CREATE (e:Evidence {
  evidence_id: $evidence_id,
  evidence_type: $type,  // 'alert' | 'log' | 'telemetry' | 'enrichment'
  
  // Provenance
  source_system: $source,  // 'crowdstrike' | 'sentinel' | 'okta' | etc.
  connector: $connector,
  ingest_pipeline_step: $pipeline_step,
  raw_event_id: $raw_id,
  
  // Bi-temporal (CRITICAL for gap detection)
  t_valid: $event_timestamp,      // When event occurred in real world
  t_invalid: $event_end_time,     // When event ceased (for duration events)
  t_created: datetime(),          // When we ingested it
  t_expired: null,
  
  // Ingestion latency (pre-computed for query efficiency)
  ingestion_delta_ms: duration.inMillis(datetime(), $event_timestamp),
  
  // Mapping semantics
  fields_present: $fields,        // List of normalized field names present
  high_value_fields_count: $hv_count,  // Count of identity/entity fields
  supporting_fields_count: $sf_count,
  mapping_quality_score: $quality,  // 0.0 - 1.0
  
  // Identity stitching quality
  stitch_quality: $stitch_score,  // 0.0 - 1.0
  canonical_entities: $entities   // List of resolved canonical IDs
})

// ============================================================
// POLICY EVALUATION NODE
// ============================================================
CREATE (p:PolicyEval {
  policy_eval_id: $eval_id,
  policy_id: $policy_id,
  policy_version: $policy_version,
  policy_name: $policy_name,
  
  // Scoring context
  scoring_config_version: $scoring_version,
  base_score: $base_score,
  context_multipliers: $multipliers,  // JSON object of applied multipliers
  final_score: $final_score,
  
  // Bi-temporal
  t_valid: $eval_time,
  t_invalid: null,
  t_created: datetime(),
  t_expired: null,
  
  // Evaluation details
  conditions_evaluated: $conditions,  // JSON array of condition results
  thresholds_applied: $thresholds,
  exceptions_checked: $exception_ids
})

// ============================================================
// EXCEPTION NODE
// ============================================================
CREATE (ex:Exception {
  exception_id: $exception_id,
  exception_type: $type,  // 'whitelist' | 'service_account' | 'maintenance_window' | 'manual_override'
  
  // Justification (for audit)
  justification: $justification,
  approved_by: $approver,
  approval_timestamp: $approval_time,
  expiry: $expiry_time,
  
  // Bi-temporal
  t_valid: $effective_start,
  t_invalid: $effective_end,
  t_created: datetime(),
  t_expired: null,
  
  // Scope
  applies_to_entities: $entity_ids,
  applies_to_policies: $policy_ids
})

// ============================================================
// OUTCOME NODE
// ============================================================
CREATE (o:Outcome {
  outcome_id: $outcome_id,
  action_type: $type,  // 'incident_created' | 'recommendation' | 'suppressed' | 'escalated'
  
  // Action details
  severity: $severity,
  incident_id: $incident_id,  // If incident created
  recommendations: $recommendations,  // JSON array
  
  // Bi-temporal
  t_valid: $action_time,
  t_invalid: null,
  t_created: datetime(),
  t_expired: null,
  
  // TTL for cleanup
  ttl_seconds: $ttl
})
```

### Relationship Creation Templates

```cypher
// ============================================================
// CORE RELATIONSHIPS
// ============================================================

// Session contains decisions
MATCH (s:Session {session_id: $session_id})
MATCH (d:Decision {decision_id: $decision_id})
CREATE (s)-[:CONTAINS {
  order: $sequence_order,
  t_created: datetime()
}]->(d)

// Decision consumes evidence
MATCH (d:Decision {decision_id: $decision_id})
MATCH (e:Evidence {evidence_id: $evidence_id})
CREATE (d)-[:CONSUMES {
  relevance_score: $relevance,
  contribution_weight: $weight,
  t_created: datetime()
}]->(e)

// Decision evaluates policy
MATCH (d:Decision {decision_id: $decision_id})
MATCH (p:PolicyEval {policy_eval_id: $eval_id})
CREATE (d)-[:EVALUATES {
  evaluation_order: $order,
  t_created: datetime()
}]->(p)

// Policy invoked exception
MATCH (p:PolicyEval {policy_eval_id: $eval_id})
MATCH (ex:Exception {exception_id: $exception_id})
CREATE (p)-[:INVOKED_EXCEPTION {
  match_reason: $reason,
  t_created: datetime()
}]->(ex)

// Decision produces outcome
MATCH (d:Decision {decision_id: $decision_id})
MATCH (o:Outcome {outcome_id: $outcome_id})
CREATE (d)-[:PRODUCES {
  t_created: datetime()
}]->(o)

// Evidence observed on domain entity
MATCH (e:Evidence {evidence_id: $evidence_id})
MATCH (entity) WHERE entity.canonical_id = $canonical_id
CREATE (e)-[:OBSERVED_ON {
  observation_type: $obs_type,  // 'source' | 'target' | 'actor' | 'resource'
  field_path: $field_path,      // Original field that contained this entity
  confidence: $confidence,
  t_created: datetime()
}]->(entity)

// Precedent reference (populated async via similarity matching)
MATCH (d:Decision {decision_id: $decision_id})
MATCH (p:Decision {decision_id: $precedent_id})
CREATE (d)-[:REFERENCES_PRECEDENT {
  similarity_score: $similarity,
  similarity_method: $method,  // 'embedding_cosine' | 'graph_kernel' | 'factor_overlap'
  t_created: datetime()
}]->(p)
```

---

## ExplanationCache Pattern

### Purpose

Pre-computed explanation paths eliminate runtime traversal for analyst triage, reducing P95 latency from 500ms+ to <50ms for the T1 Decision Trace Explainer card.

### Schema Definition

```cypher
// ============================================================
// EXPLANATION CACHE NODE
// ============================================================
CREATE (x:ExplanationCache {
  explanation_id: $explanation_id,
  decision_id: $decision_id,
  
  // Human-readable explanation
  natural_language: $nl_explanation,
  
  // Structured path for UI rendering
  path_nodes: $node_ids,          // Ordered list of node IDs in explanation path
  path_relationships: $rel_types,  // Relationship types traversed
  path_summary: $summary,          // JSON with node labels and key properties
  
  // Explanation metadata
  explanation_type: $type,  // 'triage_summary' | 'blast_radius' | 'attack_chain' | 'policy_trace'
  explanation_depth: $depth,  // Number of hops
  
  // Generation metadata
  generated_at: datetime(),
  generator_version: $generator_version,
  ttl_seconds: $ttl,
  
  // Quality indicators
  evidence_count: $evidence_count,
  policy_count: $policy_count,
  entity_count: $entity_count,
  confidence: $confidence
})

// Link to decision
MATCH (d:Decision {decision_id: $decision_id})
MATCH (x:ExplanationCache {explanation_id: $explanation_id})
CREATE (d)-[:EXPLAINED_BY {
  explanation_type: $type,
  is_primary: $is_primary,  // True for default triage view
  t_created: datetime()
}]->(x)
```

### Explanation Generation Logic

```python
# ============================================================
# explanation_generator.py
# ============================================================

from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime
import hashlib

@dataclass
class ExplanationPath:
    """Structured explanation path for caching."""
    nodes: List[str]           # Node IDs in traversal order
    relationships: List[str]   # Relationship types
    natural_language: str      # Human-readable summary
    explanation_type: str
    confidence: float

class ExplanationGenerator:
    """
    Generates pre-computed explanations for Decision nodes.
    
    Called asynchronously after decision creation to populate
    ExplanationCache without blocking real-time processing.
    """
    
    EXPLANATION_TEMPLATES = {
        'alert_correlation': (
            "{severity} alert triggered because {actor} {action} {target} "
            "from {source_context}. {policy_match_reason}. "
            "{temporal_context}."
        ),
        'lateral_movement': (
            "Potential lateral movement detected: {actor} accessed "
            "{hop_count} systems ({systems_list}) within {time_window}. "
            "Path: {path_summary}."
        ),
        'policy_exception': (
            "Alert suppressed by {exception_type} exception: {justification}. "
            "Exception approved by {approver} on {approval_date}, "
            "valid until {expiry}."
        ),
        'blast_radius': (
            "Blast radius assessment: {affected_count} entities potentially "
            "impacted. Critical assets: {critical_assets}. "
            "Maximum path depth: {max_depth} hops."
        )
    }
    
    def __init__(self, graph_client, llm_client=None):
        self.graph = graph_client
        self.llm = llm_client  # Optional: for enhanced natural language
    
    async def generate_triage_explanation(
        self, 
        decision_id: str
    ) -> ExplanationPath:
        """
        Generate T1 analyst triage explanation.
        
        Traverses: Decision -> Evidence -> Entity
                   Decision -> PolicyEval -> Exception
                   Decision -> Outcome
        """
        # Fetch decision context (max 2 hops for triage)
        query = """
        MATCH (d:Decision {decision_id: $decision_id})
        OPTIONAL MATCH (d)-[c:CONSUMES]->(e:Evidence)
        OPTIONAL MATCH (e)-[o:OBSERVED_ON]->(entity)
        OPTIONAL MATCH (d)-[:EVALUATES]->(p:PolicyEval)
        OPTIONAL MATCH (p)-[:INVOKED_EXCEPTION]->(ex:Exception)
        OPTIONAL MATCH (d)-[:PRODUCES]->(out:Outcome)
        RETURN d, 
               collect(DISTINCT {evidence: e, rel: c, entity: entity, obs: o}) as evidence_paths,
               collect(DISTINCT {policy: p, exception: ex}) as policy_paths,
               out
        """
        
        result = await self.graph.execute(query, {'decision_id': decision_id})
        
        if not result:
            return None
        
        decision = result['d']
        evidence_paths = result['evidence_paths']
        policy_paths = result['policy_paths']
        outcome = result['out']
        
        # Build explanation components
        components = self._extract_explanation_components(
            decision, evidence_paths, policy_paths, outcome
        )
        
        # Generate natural language
        nl_explanation = self._render_template(
            'alert_correlation',
            components
        )
        
        # If LLM available, enhance the explanation
        if self.llm and components.get('needs_enhancement'):
            nl_explanation = await self._llm_enhance(nl_explanation, components)
        
        # Build path structure
        path_nodes = [decision_id]
        path_rels = []
        
        for ep in evidence_paths:
            if ep['evidence']:
                path_nodes.append(ep['evidence']['evidence_id'])
                path_rels.append('CONSUMES')
                if ep['entity']:
                    path_nodes.append(ep['entity']['canonical_id'])
                    path_rels.append('OBSERVED_ON')
        
        return ExplanationPath(
            nodes=path_nodes,
            relationships=path_rels,
            natural_language=nl_explanation,
            explanation_type='triage_summary',
            confidence=self._calculate_confidence(components)
        )
    
    async def generate_blast_radius_explanation(
        self,
        decision_id: str,
        max_depth: int = 4
    ) -> ExplanationPath:
        """
        Generate T2 investigation blast radius explanation.
        
        Uses variable-length path traversal with depth limit.
        """
        query = """
        MATCH (d:Decision {decision_id: $decision_id})
        MATCH (d)-[:CONSUMES]->(e:Evidence)-[:OBSERVED_ON]->(start_entity)
        
        // Variable-length path to find connected entities
        MATCH path = (start_entity)-[*1..$max_depth]-(connected)
        WHERE connected:Identity OR connected:Device OR connected:Host 
              OR connected:CloudResource
        
        // Aggregate affected entities
        WITH d, start_entity, 
             collect(DISTINCT connected) as affected_entities,
             collect(DISTINCT path) as paths
        
        // Calculate criticality
        UNWIND affected_entities as ae
        OPTIONAL MATCH (ae)-[:HAS_CRITICALITY]->(crit:AssetCriticality)
        
        RETURN d,
               start_entity,
               affected_entities,
               collect(DISTINCT {entity: ae, criticality: crit}) as entity_criticalities,
               size(affected_entities) as affected_count,
               $max_depth as max_depth
        """
        
        result = await self.graph.execute(query, {
            'decision_id': decision_id,
            'max_depth': max_depth
        })
        
        if not result:
            return None
        
        # Build blast radius explanation
        critical_assets = [
            ec['entity']['canonical_id'] 
            for ec in result['entity_criticalities']
            if ec['criticality'] and ec['criticality'].get('level') == 'critical'
        ]
        
        components = {
            'affected_count': result['affected_count'],
            'critical_assets': ', '.join(critical_assets[:5]) or 'None identified',
            'max_depth': result['max_depth']
        }
        
        nl_explanation = self._render_template('blast_radius', components)
        
        # Build path nodes (start + sample of affected)
        path_nodes = [decision_id, result['start_entity']['canonical_id']]
        path_nodes.extend([
            e['canonical_id'] 
            for e in result['affected_entities'][:10]  # Limit for UI
        ])
        
        return ExplanationPath(
            nodes=path_nodes,
            relationships=['CONSUMES', 'OBSERVED_ON'] + ['CONNECTED_TO'] * (len(path_nodes) - 2),
            natural_language=nl_explanation,
            explanation_type='blast_radius',
            confidence=0.8 if critical_assets else 0.6
        )
    
    def _extract_explanation_components(
        self,
        decision: dict,
        evidence_paths: List[dict],
        policy_paths: List[dict],
        outcome: dict
    ) -> dict:
        """Extract template variables from graph data."""
        
        # Find primary actor (Identity node)
        actor = None
        target = None
        source_context = []
        
        for ep in evidence_paths:
            entity = ep.get('entity')
            if not entity:
                continue
            
            obs_type = ep.get('obs', {}).get('observation_type')
            
            if obs_type == 'actor' and 'Identity' in entity.get('labels', []):
                actor = entity.get('user') or entity.get('upn') or entity.get('canonical_id')
            elif obs_type == 'target':
                target = entity.get('canonical_id')
            elif obs_type == 'source':
                source_context.append(
                    f"{entity.get('ip_address', '')} ({entity.get('geo_location', 'unknown')})"
                )
        
        # Determine action from evidence type
        evidence_types = [ep['evidence'].get('evidence_type') for ep in evidence_paths if ep.get('evidence')]
        action = self._infer_action(evidence_types, decision.get('decision_type'))
        
        # Policy match reason
        policy_reasons = []
        for pp in policy_paths:
            if pp.get('policy'):
                policy_reasons.append(pp['policy'].get('policy_name', 'Unknown policy'))
        
        # Temporal context
        t_valid = decision.get('t_valid')
        temporal_context = f"Detected at {t_valid}" if t_valid else "Detection time unknown"
        
        return {
            'severity': decision.get('severity', 'Medium'),
            'actor': actor or 'Unknown actor',
            'action': action,
            'target': target or 'unknown target',
            'source_context': ', '.join(source_context) or 'unknown source',
            'policy_match_reason': f"Matched policies: {', '.join(policy_reasons)}" if policy_reasons else "No policy match recorded",
            'temporal_context': temporal_context,
            'needs_enhancement': not actor or not target
        }
    
    def _render_template(self, template_name: str, components: dict) -> str:
        """Render explanation template with components."""
        template = self.EXPLANATION_TEMPLATES.get(template_name, "{severity} alert detected.")
        try:
            return template.format(**components)
        except KeyError as e:
            # Fallback for missing components
            return f"{components.get('severity', 'Medium')} alert detected. Details: {components}"
    
    def _infer_action(self, evidence_types: List[str], decision_type: str) -> str:
        """Infer human-readable action from evidence types."""
        if 'authentication_failure' in evidence_types:
            return 'failed authentication to'
        elif 'file_access' in evidence_types:
            return 'accessed sensitive file on'
        elif 'network_connection' in evidence_types:
            return 'established connection to'
        elif 'process_execution' in evidence_types:
            return 'executed suspicious process on'
        else:
            return 'performed suspicious activity on'
    
    def _calculate_confidence(self, components: dict) -> float:
        """Calculate explanation confidence based on component completeness."""
        score = 0.5  # Base confidence
        
        if components.get('actor') != 'Unknown actor':
            score += 0.2
        if components.get('target') != 'unknown target':
            score += 0.15
        if 'No policy match' not in components.get('policy_match_reason', ''):
            score += 0.15
        
        return min(score, 1.0)
    
    async def _llm_enhance(self, base_explanation: str, components: dict) -> str:
        """Use LLM to enhance explanation quality."""
        prompt = f"""
        Improve this security alert explanation for a SOC analyst. 
        Keep it concise (2-3 sentences max). Maintain technical accuracy.
        Do not add information not present in the original.
        
        Original: {base_explanation}
        
        Context: Severity={components.get('severity')}, 
                 Actor={components.get('actor')},
                 Target={components.get('target')}
        
        Improved explanation:
        """
        
        response = await self.llm.complete(prompt, max_tokens=150)
        return response.strip()


# ============================================================
# Explanation Cache Writer
# ============================================================

async def cache_explanation(
    graph_client,
    decision_id: str,
    explanation: ExplanationPath
) -> str:
    """Persist explanation to graph and return explanation_id."""
    
    explanation_id = hashlib.sha256(
        f"{decision_id}:{explanation.explanation_type}:{datetime.utcnow().isoformat()}".encode()
    ).hexdigest()[:16]
    
    query = """
    MATCH (d:Decision {decision_id: $decision_id})
    CREATE (x:ExplanationCache {
      explanation_id: $explanation_id,
      decision_id: $decision_id,
      natural_language: $natural_language,
      path_nodes: $path_nodes,
      path_relationships: $path_relationships,
      explanation_type: $explanation_type,
      explanation_depth: $depth,
      generated_at: datetime(),
      generator_version: $generator_version,
      ttl_seconds: $ttl,
      confidence: $confidence
    })
    CREATE (d)-[:EXPLAINED_BY {
      explanation_type: $explanation_type,
      is_primary: $is_primary,
      t_created: datetime()
    }]->(x)
    RETURN x.explanation_id as id
    """
    
    result = await graph_client.execute(query, {
        'decision_id': decision_id,
        'explanation_id': explanation_id,
        'natural_language': explanation.natural_language,
        'path_nodes': explanation.nodes,
        'path_relationships': explanation.relationships,
        'explanation_type': explanation.explanation_type,
        'depth': len(explanation.nodes),
        'generator_version': '1.0.0',
        'ttl': 86400 * 7,  # 7 days
        'confidence': explanation.confidence,
        'is_primary': explanation.explanation_type == 'triage_summary'
    })
    
    return result['id']
```

### Explanation Retrieval Query

```cypher
// ============================================================
// Fast explanation retrieval for T1 triage (target: <50ms)
// ============================================================

// Get primary explanation for decision
MATCH (d:Decision {decision_id: $decision_id})
       -[:EXPLAINED_BY {is_primary: true}]->
       (x:ExplanationCache)
WHERE x.ttl_seconds > duration.inSeconds(datetime(), x.generated_at)
RETURN x.natural_language as explanation,
       x.path_nodes as path,
       x.confidence as confidence,
       x.generated_at as generated

// If no cached explanation, generate on-demand (fallback)
// This query is more expensive and should trigger async cache population
MATCH (d:Decision {decision_id: $decision_id})
WHERE NOT EXISTS {
  MATCH (d)-[:EXPLAINED_BY]->(:ExplanationCache)
}
OPTIONAL MATCH (d)-[:CONSUMES]->(e:Evidence)
OPTIONAL MATCH (d)-[:EVALUATES]->(p:PolicyEval)
OPTIONAL MATCH (d)-[:PRODUCES]->(o:Outcome)
RETURN d.decision_id as decision_id,
       d.severity as severity,
       d.explainable_factors as factors,
       collect(DISTINCT e.evidence_type) as evidence_types,
       collect(DISTINCT p.policy_name) as policies,
       o.action_type as outcome
```

---

## Ingestion Anomaly Detection

### The Bi-Temporal Delta Approach

This is a novel application of bi-temporal modeling for SOC blind-spot detection. The core insight: the difference between `t_valid` (when an event occurred) and `t_created` (when we ingested it) reveals telemetry health.

```
┌─────────────────────────────────────────────────────────────────┐
│              INGESTION DELTA DISTRIBUTION                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Normal Distribution (per source)                               │
│                                                                 │
│     │                    ╭──────╮                               │
│     │                   ╱        ╲                              │
│     │                  ╱          ╲                             │
│     │                 ╱            ╲                            │
│  F  │               ╱              ╲                            │
│  r  │              ╱                ╲                           │
│  e  │            ╱                  ╲                           │
│  q  │          ╱                    ╲                           │
│     │        ╱                      ╲                           │
│     │──────╱                        ╲───────────────────────    │
│     └────────────────────────────────────────────────────────▶  │
│           μ-3σ    μ-2σ    μ    μ+2σ   μ+3σ                      │
│                                                                 │
│  Anomaly Zones:                                                 │
│  ├── δ < μ-3σ: Suspiciously fast (clock skew? replay?)         │
│  ├── δ > μ+3σ: Critically delayed (blind spot!)                │
│  └── Missing events: Gap detection via expected volume         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Ingestion Health Schema

```cypher
// ============================================================
// INGESTION HEALTH TRACKING NODES
// ============================================================

// Per-source ingestion statistics (updated continuously)
CREATE (ih:IngestionHealth {
  source_system: $source,
  connector: $connector,
  
  // EWMA statistics for delta distribution
  ewma_delta_ms: $ewma_delta,
  ewma_delta_variance: $ewma_variance,
  ewma_alpha: 0.1,  // Smoothing factor
  
  // Volume tracking
  expected_events_per_minute: $expected_volume,
  observed_events_last_minute: $observed_volume,
  volume_ratio: $volume_ratio,
  
  // Health indicators
  health_status: $status,  // 'healthy' | 'degraded' | 'critical' | 'unknown'
  last_event_received: $last_received,
  consecutive_gaps: $gap_count,
  
  // Thresholds (configurable per source)
  latency_warning_ms: $warn_threshold,
  latency_critical_ms: $crit_threshold,
  volume_drop_threshold: 0.5,  // Alert if <50% expected volume
  
  // Metadata
  updated_at: datetime()
})

// Individual gap detection events
CREATE (g:IngestionGap {
  gap_id: $gap_id,
  source_system: $source,
  connector: $connector,
  
  // Gap details
  gap_type: $type,  // 'latency_spike' | 'volume_drop' | 'complete_outage' | 'clock_skew'
  gap_start: $start_time,
  gap_end: $end_time,
  gap_duration_seconds: $duration,
  
  // Impact assessment
  estimated_missing_events: $missing_count,
  affected_entity_types: $entity_types,
  blind_spot_severity: $severity,  // 'low' | 'medium' | 'high' | 'critical'
  
  // Bi-temporal
  t_valid: $gap_start,
  t_invalid: $gap_end,
  t_created: datetime(),
  t_expired: null
})

// Link gaps to affected sessions
MATCH (g:IngestionGap {gap_id: $gap_id})
MATCH (s:Session)
WHERE s.correlation_window_start <= g.gap_end 
  AND s.correlation_window_end >= g.gap_start
CREATE (s)-[:AFFECTED_BY_GAP {
  overlap_seconds: $overlap,
  confidence_impact: $impact
}]->(g)
```

### Ingestion Anomaly Detection Logic

```python
# ============================================================
# ingestion_anomaly_detector.py
# ============================================================

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from enum import Enum
import math
from collections import defaultdict

class GapType(Enum):
    LATENCY_SPIKE = "latency_spike"
    VOLUME_DROP = "volume_drop"
    COMPLETE_OUTAGE = "complete_outage"
    CLOCK_SKEW = "clock_skew"
    LATE_ARRIVAL = "late_arrival"

class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

@dataclass
class EWMAStats:
    """Exponentially Weighted Moving Average statistics."""
    mean: float = 0.0
    variance: float = 0.0
    alpha: float = 0.1
    count: int = 0
    
    def update(self, value: float) -> None:
        """Update EWMA with new observation."""
        if self.count == 0:
            self.mean = value
            self.variance = 0.0
        else:
            delta = value - self.mean
            self.mean += self.alpha * delta
            self.variance = (1 - self.alpha) * (self.variance + self.alpha * delta * delta)
        self.count += 1
    
    @property
    def stddev(self) -> float:
        return math.sqrt(self.variance) if self.variance > 0 else 0.0

@dataclass
class IngestionHealthState:
    """Per-source ingestion health tracking."""
    source_system: str
    connector: str
    
    # Latency tracking
    delta_stats: EWMAStats = field(default_factory=EWMAStats)
    
    # Volume tracking
    volume_stats: EWMAStats = field(default_factory=EWMAStats)
    events_in_current_window: int = 0
    window_start: datetime = field(default_factory=datetime.utcnow)
    
    # Gap tracking
    last_event_time: Optional[datetime] = None
    consecutive_gaps: int = 0
    
    # Configurable thresholds
    latency_warning_ms: float = 60000.0   # 1 minute
    latency_critical_ms: float = 300000.0  # 5 minutes
    volume_drop_threshold: float = 0.5     # 50% drop
    sigma_threshold: float = 3.0           # 3 standard deviations

@dataclass
class IngestionAnomaly:
    """Detected ingestion anomaly."""
    gap_type: GapType
    source_system: str
    connector: str
    detected_at: datetime
    severity: str  # 'low', 'medium', 'high', 'critical'
    
    # Anomaly details
    observed_value: float
    expected_value: float
    deviation_sigma: float
    
    # Impact estimation
    estimated_missing_events: int = 0
    affected_time_range: Tuple[datetime, datetime] = None
    
    # Factor generation
    factor_name: str = ""
    factor_weight: float = 0.0

class IngestionAnomalyDetector:
    """
    Detects ingestion anomalies using bi-temporal delta analysis.
    
    Novel approach: Uses the gap between t_valid (event time) and 
    t_created (ingestion time) to detect telemetry health issues.
    """
    
    def __init__(
        self,
        window_size_seconds: int = 60,
        ewma_alpha: float = 0.1
    ):
        self.window_size = window_size_seconds
        self.ewma_alpha = ewma_alpha
        self.source_health: Dict[str, IngestionHealthState] = {}
        self.detected_anomalies: List[IngestionAnomaly] = []
    
    def get_source_key(self, source_system: str, connector: str) -> str:
        """Generate unique key for source+connector combination."""
        return f"{source_system}:{connector}"
    
    def get_or_create_health_state(
        self, 
        source_system: str, 
        connector: str
    ) -> IngestionHealthState:
        """Get or initialize health state for a source."""
        key = self.get_source_key(source_system, connector)
        
        if key not in self.source_health:
            self.source_health[key] = IngestionHealthState(
                source_system=source_system,
                connector=connector,
                delta_stats=EWMAStats(alpha=self.ewma_alpha),
                volume_stats=EWMAStats(alpha=self.ewma_alpha)
            )
        
        return self.source_health[key]
    
    def process_evidence(
        self,
        evidence_id: str,
        source_system: str,
        connector: str,
        t_valid: datetime,
        t_created: datetime
    ) -> List[IngestionAnomaly]:
        """
        Process incoming evidence and detect anomalies.
        
        Returns list of detected anomalies (may be empty).
        """
        anomalies = []
        state = self.get_or_create_health_state(source_system, connector)
        
        # Calculate ingestion delta
        delta_ms = (t_created - t_valid).total_seconds() * 1000
        
        # 1. Check for clock skew (negative or suspiciously small delta)
        if delta_ms < 0:
            anomaly = self._create_anomaly(
                GapType.CLOCK_SKEW,
                state,
                observed=delta_ms,
                expected=state.delta_stats.mean,
                deviation=abs(delta_ms - state.delta_stats.mean) / max(state.delta_stats.stddev, 1)
            )
            anomaly.factor_name = "clock_skew_detected"
            anomaly.factor_weight = 0.3  # Moderate concern
            anomalies.append(anomaly)
        
        # 2. Check for latency anomaly (statistical outlier)
        elif state.delta_stats.count > 10:  # Need baseline first
            deviation_sigma = (delta_ms - state.delta_stats.mean) / max(state.delta_stats.stddev, 1)
            
            if deviation_sigma > state.sigma_threshold:
                # Late arrival - potential blind spot
                severity = self._calculate_severity(
                    delta_ms,
                    state.latency_warning_ms,
                    state.latency_critical_ms
                )
                
                anomaly = self._create_anomaly(
                    GapType.LATENCY_SPIKE,
                    state,
                    observed=delta_ms,
                    expected=state.delta_stats.mean,
                    deviation=deviation_sigma,
                    severity=severity
                )
                anomaly.factor_name = "ingestion_latency_spike"
                anomaly.factor_weight = 0.2 if severity == 'low' else 0.4 if severity == 'medium' else 0.6
                anomaly.affected_time_range = (
                    t_valid,
                    t_valid + timedelta(milliseconds=delta_ms)
                )
                anomalies.append(anomaly)
            
            elif deviation_sigma < -state.sigma_threshold:
                # Suspiciously fast - could indicate replay attack
                anomaly = self._create_anomaly(
                    GapType.CLOCK_SKEW,
                    state,
                    observed=delta_ms,
                    expected=state.delta_stats.mean,
                    deviation=abs(deviation_sigma)
                )
                anomaly.factor_name = "suspiciously_fast_ingestion"
                anomaly.factor_weight = 0.25
                anomalies.append(anomaly)
        
        # 3. Update EWMA (after anomaly detection to not pollute baseline)
        if delta_ms >= 0 and delta_ms < state.latency_critical_ms * 2:
            # Only update baseline with reasonable values
            state.delta_stats.update(delta_ms)
        
        # 4. Update volume tracking
        self._update_volume_tracking(state, t_created)
        
        # 5. Update last event time
        state.last_event_time = t_created
        state.consecutive_gaps = 0  # Reset on successful receipt
        
        return anomalies
    
    def check_volume_gaps(self) -> List[IngestionAnomaly]:
        """
        Periodic check for volume-based gaps.
        Call this every window_size seconds.
        """
        anomalies = []
        current_time = datetime.utcnow()
        
        for key, state in self.source_health.items():
            # Check if we've completed a window
            window_elapsed = (current_time - state.window_start).total_seconds()
            
            if window_elapsed >= self.window_size:
                # Calculate volume ratio
                expected_volume = state.volume_stats.mean if state.volume_stats.count > 5 else None
                observed_volume = state.events_in_current_window
                
                if expected_volume and expected_volume > 0:
                    volume_ratio = observed_volume / expected_volume
                    
                    if volume_ratio < state.volume_drop_threshold:
                        # Significant volume drop
                        missing_events = int(expected_volume - observed_volume)
                        
                        anomaly = self._create_anomaly(
                            GapType.VOLUME_DROP,
                            state,
                            observed=observed_volume,
                            expected=expected_volume,
                            deviation=(expected_volume - observed_volume) / max(state.volume_stats.stddev, 1)
                        )
                        anomaly.estimated_missing_events = missing_events
                        anomaly.factor_name = "volume_drop_detected"
                        anomaly.factor_weight = 0.5 if volume_ratio < 0.2 else 0.3
                        anomaly.affected_time_range = (
                            state.window_start,
                            current_time
                        )
                        anomalies.append(anomaly)
                    
                    elif volume_ratio == 0:
                        # Complete outage
                        anomaly = self._create_anomaly(
                            GapType.COMPLETE_OUTAGE,
                            state,
                            observed=0,
                            expected=expected_volume,
                            deviation=float('inf'),
                            severity='critical'
                        )
                        anomaly.estimated_missing_events = int(expected_volume)
                        anomaly.factor_name = "complete_ingestion_outage"
                        anomaly.factor_weight = 0.8
                        state.consecutive_gaps += 1
                        anomalies.append(anomaly)
                
                # Update volume baseline and reset window
                if observed_volume > 0:
                    state.volume_stats.update(observed_volume)
                state.events_in_current_window = 0
                state.window_start = current_time
        
        return anomalies
    
    def check_stale_sources(
        self, 
        stale_threshold_seconds: int = 300
    ) -> List[IngestionAnomaly]:
        """
        Check for sources that haven't sent data recently.
        """
        anomalies = []
        current_time = datetime.utcnow()
        
        for key, state in self.source_health.items():
            if state.last_event_time:
                silence_duration = (current_time - state.last_event_time).total_seconds()
                
                if silence_duration > stale_threshold_seconds:
                    severity = self._calculate_severity(
                        silence_duration * 1000,
                        stale_threshold_seconds * 1000,
                        stale_threshold_seconds * 3000
                    )
                    
                    anomaly = self._create_anomaly(
                        GapType.COMPLETE_OUTAGE,
                        state,
                        observed=silence_duration,
                        expected=self.window_size,
                        deviation=silence_duration / self.window_size,
                        severity=severity
                    )
                    anomaly.factor_name = "source_silence_detected"
                    anomaly.factor_weight = 0.6 if severity == 'high' else 0.4
                    anomaly.affected_time_range = (
                        state.last_event_time,
                        current_time
                    )
                    anomalies.append(anomaly)
        
        return anomalies
    
    def get_health_status(
        self, 
        source_system: str, 
        connector: str
    ) -> HealthStatus:
        """Get current health status for a source."""
        key = self.get_source_key(source_system, connector)
        state = self.source_health.get(key)
        
        if not state:
            return HealthStatus.UNKNOWN
        
        if state.consecutive_gaps >= 3:
            return HealthStatus.CRITICAL
        elif state.consecutive_gaps >= 1:
            return HealthStatus.DEGRADED
        
        # Check recent latency
        if state.delta_stats.mean > state.latency_critical_ms:
            return HealthStatus.CRITICAL
        elif state.delta_stats.mean > state.latency_warning_ms:
            return HealthStatus.DEGRADED
        
        return HealthStatus.HEALTHY
    
    def get_blind_spot_risk(self) -> Dict[str, float]:
        """
        Calculate overall blind spot risk per domain.
        
        Returns risk scores (0.0-1.0) by domain.
        """
        domain_risks = defaultdict(list)
        
        for key, state in self.source_health.items():
            # Map source to domain (simplified - would need config in production)
            domain = self._infer_domain(state.source_system)
            
            # Calculate risk components
            latency_risk = min(state.delta_stats.mean / state.latency_critical_ms, 1.0)
            
            volume_risk = 0.0
            if state.volume_stats.count > 0 and state.volume_stats.mean > 0:
                current_ratio = state.events_in_current_window / state.volume_stats.mean
                volume_risk = max(0, 1 - current_ratio)
            
            gap_risk = min(state.consecutive_gaps / 5, 1.0)
            
            # Weighted combination
            source_risk = (latency_risk * 0.3 + volume_risk * 0.4 + gap_risk * 0.3)
            domain_risks[domain].append(source_risk)
        
        # Aggregate per domain (worst-case)
        return {
            domain: max(risks) if risks else 0.0
            for domain, risks in domain_risks.items()
        }
    
    def _update_volume_tracking(
        self, 
        state: IngestionHealthState, 
        t_created: datetime
    ) -> None:
        """Update volume tracking for windowed analysis."""
        # Check if we're still in the same window
        window_elapsed = (t_created - state.window_start).total_seconds()
        
        if window_elapsed < self.window_size:
            state.events_in_current_window += 1
        else:
            # Window rolled over - this will be handled by check_volume_gaps()
            state.events_in_current_window = 1
            state.window_start = t_created
    
    def _create_anomaly(
        self,
        gap_type: GapType,
        state: IngestionHealthState,
        observed: float,
        expected: float,
        deviation: float,
        severity: str = None
    ) -> IngestionAnomaly:
        """Create an anomaly record."""
        if severity is None:
            severity = 'medium' if deviation > 3 else 'low'
            if deviation > 5:
                severity = 'high'
            if deviation > 10:
                severity = 'critical'
        
        return IngestionAnomaly(
            gap_type=gap_type,
            source_system=state.source_system,
            connector=state.connector,
            detected_at=datetime.utcnow(),
            severity=severity,
            observed_value=observed,
            expected_value=expected,
            deviation_sigma=deviation
        )
    
    def _calculate_severity(
        self,
        value_ms: float,
        warning_threshold: float,
        critical_threshold: float
    ) -> str:
        """Calculate severity based on thresholds."""
        if value_ms >= critical_threshold:
            return 'critical'
        elif value_ms >= warning_threshold:
            return 'high'
        elif value_ms >= warning_threshold * 0.5:
            return 'medium'
        return 'low'
    
    def _infer_domain(self, source_system: str) -> str:
        """Infer security domain from source system."""
        source_lower = source_system.lower()
        
        if any(x in source_lower for x in ['crowdstrike', 'defender', 'sentinelone', 'carbon']):
            return 'endpoint'
        elif any(x in source_lower for x in ['okta', 'azure_ad', 'ping', 'auth0']):
            return 'identity'
        elif any(x in source_lower for x in ['palo', 'fortinet', 'cisco', 'zscaler']):
            return 'network'
        elif any(x in source_lower for x in ['aws', 'gcp', 'azure', 'cloudtrail']):
            return 'cloud'
        elif any(x in source_lower for x in ['o365', 'google_workspace', 'proofpoint']):
            return 'email'
        return 'other'


# ============================================================
# Integration with JanuSec Pipeline
# ============================================================

class IngestionHealthIntegration:
    """
    Integration layer between anomaly detection and JanuSec pipeline.
    """
    
    def __init__(self, detector: IngestionAnomalyDetector, graph_client):
        self.detector = detector
        self.graph = graph_client
    
    async def on_evidence_ingested(
        self,
        evidence_id: str,
        source_system: str,
        connector: str,
        t_valid: datetime,
        t_created: datetime,
        session_id: Optional[str] = None
    ) -> List[dict]:
        """
        Called when evidence is ingested. Returns factors to add to session.
        """
        anomalies = self.detector.process_evidence(
            evidence_id, source_system, connector, t_valid, t_created
        )
        
        factors = []
        for anomaly in anomalies:
            # Persist to graph
            await self._persist_anomaly(anomaly)
            
            # Generate factor for session scoring
            factor = {
                'factor_name': anomaly.factor_name,
                'factor_weight': anomaly.factor_weight,
                'source': f"{anomaly.source_system}:{anomaly.connector}",
                'details': {
                    'gap_type': anomaly.gap_type.value,
                    'observed': anomaly.observed_value,
                    'expected': anomaly.expected_value,
                    'deviation_sigma': anomaly.deviation_sigma,
                    'severity': anomaly.severity
                }
            }
            factors.append(factor)
            
            # Link to session if provided
            if session_id:
                await self._link_anomaly_to_session(anomaly, session_id)
        
        return factors
    
    async def get_domain_health_summary(self) -> dict:
        """
        Get health summary for Multi-Domain Health panel.
        """
        blind_spot_risks = self.detector.get_blind_spot_risk()
        
        summary = {
            'overall_health': 'healthy',
            'domains': {},
            'active_gaps': [],
            'blind_spot_risk_score': 0.0
        }
        
        max_risk = 0.0
        for domain, risk in blind_spot_risks.items():
            max_risk = max(max_risk, risk)
            
            # Get detailed status per source in domain
            domain_sources = [
                (key, state) for key, state in self.detector.source_health.items()
                if self.detector._infer_domain(state.source_system) == domain
            ]
            
            summary['domains'][domain] = {
                'health_status': self._risk_to_status(risk),
                'blind_spot_risk': risk,
                'source_count': len(domain_sources),
                'sources': [
                    {
                        'name': state.source_system,
                        'connector': state.connector,
                        'status': self.detector.get_health_status(
                            state.source_system, state.connector
                        ).value,
                        'avg_latency_ms': state.delta_stats.mean,
                        'last_seen': state.last_event_time.isoformat() if state.last_event_time else None
                    }
                    for _, state in domain_sources
                ]
            }
        
        summary['blind_spot_risk_score'] = max_risk
        summary['overall_health'] = self._risk_to_status(max_risk)
        
        return summary
    
    async def _persist_anomaly(self, anomaly: IngestionAnomaly) -> str:
        """Persist anomaly to graph database."""
        import hashlib
        
        gap_id = hashlib.sha256(
            f"{anomaly.source_system}:{anomaly.connector}:{anomaly.detected_at.isoformat()}".encode()
        ).hexdigest()[:16]
        
        query = """
        CREATE (g:IngestionGap {
          gap_id: $gap_id,
          source_system: $source_system,
          connector: $connector,
          gap_type: $gap_type,
          detected_at: $detected_at,
          severity: $severity,
          observed_value: $observed,
          expected_value: $expected,
          deviation_sigma: $deviation,
          estimated_missing_events: $missing_events,
          t_valid: $t_valid,
          t_created: datetime()
        })
        RETURN g.gap_id as id
        """
        
        result = await self.graph.execute(query, {
            'gap_id': gap_id,
            'source_system': anomaly.source_system,
            'connector': anomaly.connector,
            'gap_type': anomaly.gap_type.value,
            'detected_at': anomaly.detected_at.isoformat(),
            'severity': anomaly.severity,
            'observed': anomaly.observed_value,
            'expected': anomaly.expected_value,
            'deviation': anomaly.deviation_sigma,
            'missing_events': anomaly.estimated_missing_events,
            't_valid': anomaly.affected_time_range[0].isoformat() if anomaly.affected_time_range else None
        })
        
        return result['id']
    
    async def _link_anomaly_to_session(
        self, 
        anomaly: IngestionAnomaly, 
        session_id: str
    ) -> None:
        """Link detected anomaly to affected session."""
        query = """
        MATCH (s:Session {session_id: $session_id})
        MATCH (g:IngestionGap {gap_id: $gap_id})
        CREATE (s)-[:AFFECTED_BY_GAP {
          impact_factor: $impact,
          t_created: datetime()
        }]->(g)
        """
        
        await self.graph.execute(query, {
            'session_id': session_id,
            'gap_id': anomaly.gap_type.value,  # Would use actual gap_id in production
            'impact': anomaly.factor_weight
        })
    
    def _risk_to_status(self, risk: float) -> str:
        """Convert risk score to status string."""
        if risk >= 0.7:
            return 'critical'
        elif risk >= 0.4:
            return 'degraded'
        elif risk >= 0.2:
            return 'warning'
        return 'healthy'
```

---

## Context Graph Integration Architecture

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    JANUSEC CONTEXT GRAPH ARCHITECTURE                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │ CrowdStrike │  │   Sentinel  │  │    Okta     │  │  CloudTrail │   │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘   │
│         │                │                │                │           │
│         ▼                ▼                ▼                ▼           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     INGEST LAYER                                │   │
│  │  ┌─────────────────────────────────────────────────────────┐   │   │
│  │  │  Bi-Temporal Stamping: t_valid (event) + t_created (now) │   │   │
│  │  │  Ingestion Anomaly Detection (delta analysis)            │   │   │
│  │  └─────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────┬───────────────────────────────────┘   │
│                                │                                       │
│                                ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                   NORMALIZE / MAP LAYER                         │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │   │
│  │  │ Field Mapping │  │Entity Stitch │  │ Mapping Semantics    │  │   │
│  │  │ (to schema)   │  │(canonical ID)│  │ (quality scoring)    │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────────┘  │   │
│  └─────────────────────────────┬───────────────────────────────────┘   │
│                                │                                       │
│                                ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                   CONTEXT GRAPH STORE                           │   │
│  │                                                                 │   │
│  │   ┌─────────┐    ┌──────────┐    ┌────────────┐                │   │
│  │   │Evidence │───▶│ Decision │───▶│ PolicyEval │                │   │
│  │   └────┬────┘    └────┬─────┘    └─────┬──────┘                │   │
│  │        │              │                │                        │   │
│  │        ▼              ▼                ▼                        │   │
│  │   ┌─────────┐    ┌──────────┐    ┌────────────┐                │   │
│  │   │ Entity  │    │ Outcome  │    │ Exception  │                │   │
│  │   │ (Domain)│    └──────────┘    └────────────┘                │   │
│  │   └─────────┘                                                   │   │
│  │        │         ┌──────────────────┐                          │   │
│  │        └────────▶│ExplanationCache  │◀── Pre-computed paths    │   │
│  │                  └──────────────────┘                          │   │
│  │                                                                 │   │
│  │   Storage Options:                                              │   │
│  │   ├── In-Memory (demo/dev)                                     │   │
│  │   ├── Neo4j (production)                                       │   │
│  │   └── Neptune (AWS deployments)                                │   │
│  │                                                                 │   │
│  └─────────────────────────────┬───────────────────────────────────┘   │
│                                │                                       │
│                                ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                   CORRELATION LAYER (HopGraph)                  │   │
│  │  ┌────────────────┐  ┌────────────────┐  ┌─────────────────┐   │   │
│  │  │ Path Scoring   │  │ EWMA Smoothing │  │ Domain Diversity │   │   │
│  │  │ (blast radius) │  │ (overlap)      │  │ (coverage)       │   │   │
│  │  └────────────────┘  └────────────────┘  └─────────────────┘   │   │
│  │                                                                 │   │
│  │  Decision Trace Generation:                                     │   │
│  │  ├── Create Decision nodes per correlation step                │   │
│  │  ├── Link Evidence consumed                                    │   │
│  │  ├── Record PolicyEval with factors                            │   │
│  │  └── Generate ExplanationCache async                           │   │
│  └─────────────────────────────┬───────────────────────────────────┘   │
│                                │                                       │
│                                ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                   QUERY / API LAYER                             │   │
│  │                                                                 │   │
│  │  ┌──────────────────────┐  ┌──────────────────────────────┐    │   │
│  │  │ Session Build        │  │ Decision Trace Retrieval     │    │   │
│  │  │ POST /session/build  │  │ GET /session/{id}/trace      │    │   │
│  │  │ + as_of support      │  │ + as_of support              │    │   │
│  │  └──────────────────────┘  └──────────────────────────────┘    │   │
│  │                                                                 │   │
│  │  ┌──────────────────────┐  ┌──────────────────────────────┐    │   │
│  │  │ Explanation API      │  │ Ingestion Health API         │    │   │
│  │  │ GET /decision/{id}/  │  │ GET /health/ingestion        │    │   │
│  │  │     explanation      │  │ GET /health/blind-spots      │    │   │
│  │  └──────────────────────┘  └──────────────────────────────┘    │   │
│  └─────────────────────────────┬───────────────────────────────────┘   │
│                                │                                       │
│                                ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                   PRESENTATION LAYER (LIVE Console)             │   │
│  │                                                                 │   │
│  │  ┌────────────────┐  ┌────────────────┐  ┌─────────────────┐   │   │
│  │  │ Decision Trace │  │ Ingestion      │  │ Multi-Domain    │   │   │
│  │  │ Panel (right)  │  │ Health Banner  │  │ Health Panel    │   │   │
│  │  └────────────────┘  └────────────────┘  └─────────────────┘   │   │
│  │                                                                 │   │
│  │  ┌────────────────┐  ┌────────────────┐                        │   │
│  │  │ as_of Picker   │  │ Explanation    │                        │   │
│  │  │ (time travel)  │  │ Path Viz       │                        │   │
│  │  └────────────────┘  └────────────────┘                        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### GraphStore Interface

```python
# ============================================================
# graph_store.py - Abstraction for graph storage backends
# ============================================================

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass

@dataclass
class NodeData:
    """Generic node representation."""
    id: str
    labels: List[str]
    properties: Dict[str, Any]

@dataclass
class EdgeData:
    """Generic edge representation."""
    id: str
    type: str
    source_id: str
    target_id: str
    properties: Dict[str, Any]

@dataclass
class QueryResult:
    """Query result container."""
    nodes: List[NodeData]
    edges: List[EdgeData]
    raw: Any  # Backend-specific raw result

class GraphStore(ABC):
    """
    Abstract interface for graph storage backends.
    
    Implementations:
    - InMemoryGraphStore: For demo/testing
    - Neo4jGraphStore: For production
    - NeptuneGraphStore: For AWS deployments
    """
    
    @abstractmethod
    async def create_node(
        self,
        labels: List[str],
        properties: Dict[str, Any],
        node_id: Optional[str] = None
    ) -> str:
        """Create a node and return its ID."""
        pass
    
    @abstractmethod
    async def create_edge(
        self,
        edge_type: str,
        source_id: str,
        target_id: str,
        properties: Dict[str, Any]
    ) -> str:
        """Create an edge and return its ID."""
        pass
    
    @abstractmethod
    async def get_node(
        self,
        node_id: str,
        as_of: Optional[datetime] = None
    ) -> Optional[NodeData]:
        """Get a node by ID, optionally at a point in time."""
        pass
    
    @abstractmethod
    async def query(
        self,
        cypher: str,
        params: Dict[str, Any],
        as_of: Optional[datetime] = None
    ) -> QueryResult:
        """Execute a Cypher query."""
        pass
    
    @abstractmethod
    async def traverse(
        self,
        start_id: str,
        edge_types: List[str],
        max_depth: int = 3,
        as_of: Optional[datetime] = None
    ) -> QueryResult:
        """Traverse from a starting node."""
        pass

class InMemoryGraphStore(GraphStore):
    """
    In-memory implementation for demo and testing.
    
    Supports bi-temporal queries via property filtering.
    """
    
    def __init__(self):
        self.nodes: Dict[str, NodeData] = {}
        self.edges: Dict[str, EdgeData] = {}
        self._edge_index: Dict[str, List[str]] = {}  # source_id -> edge_ids
    
    async def create_node(
        self,
        labels: List[str],
        properties: Dict[str, Any],
        node_id: Optional[str] = None
    ) -> str:
        import uuid
        
        nid = node_id or str(uuid.uuid4())[:12]
        
        # Add bi-temporal defaults if not present
        if 't_created' not in properties:
            properties['t_created'] = datetime.utcnow().isoformat()
        
        self.nodes[nid] = NodeData(
            id=nid,
            labels=labels,
            properties=properties
        )
        
        return nid
    
    async def create_edge(
        self,
        edge_type: str,
        source_id: str,
        target_id: str,
        properties: Dict[str, Any]
    ) -> str:
        import uuid
        
        eid = str(uuid.uuid4())[:12]
        
        if 't_created' not in properties:
            properties['t_created'] = datetime.utcnow().isoformat()
        
        self.edges[eid] = EdgeData(
            id=eid,
            type=edge_type,
            source_id=source_id,
            target_id=target_id,
            properties=properties
        )
        
        # Index by source
        if source_id not in self._edge_index:
            self._edge_index[source_id] = []
        self._edge_index[source_id].append(eid)
        
        return eid
    
    async def get_node(
        self,
        node_id: str,
        as_of: Optional[datetime] = None
    ) -> Optional[NodeData]:
        node = self.nodes.get(node_id)
        
        if node and as_of:
            # Check bi-temporal validity
            if not self._is_valid_at(node.properties, as_of):
                return None
        
        return node
    
    async def query(
        self,
        cypher: str,
        params: Dict[str, Any],
        as_of: Optional[datetime] = None
    ) -> QueryResult:
        # Simplified query parsing for demo
        # Production would use a proper Cypher parser
        raise NotImplementedError("Use traverse() for in-memory store")
    
    async def traverse(
        self,
        start_id: str,
        edge_types: List[str],
        max_depth: int = 3,
        as_of: Optional[datetime] = None
    ) -> QueryResult:
        """BFS traversal with bi-temporal filtering."""
        visited_nodes = set()
        visited_edges = set()
        result_nodes = []
        result_edges = []
        
        queue = [(start_id, 0)]
        
        while queue:
            current_id, depth = queue.pop(0)
            
            if current_id in visited_nodes or depth > max_depth:
                continue
            
            visited_nodes.add(current_id)
            
            node = await self.get_node(current_id, as_of)
            if node:
                result_nodes.append(node)
            
            # Traverse edges
            for eid in self._edge_index.get(current_id, []):
                if eid in visited_edges:
                    continue
                
                edge = self.edges[eid]
                
                if edge_types and edge.type not in edge_types:
                    continue
                
                if as_of and not self._is_valid_at(edge.properties, as_of):
                    continue
                
                visited_edges.add(eid)
                result_edges.append(edge)
                queue.append((edge.target_id, depth + 1))
        
        return QueryResult(
            nodes=result_nodes,
            edges=result_edges,
            raw=None
        )
    
    def _is_valid_at(self, properties: Dict, as_of: datetime) -> bool:
        """Check if record is valid at given time."""
        t_valid = properties.get('t_valid')
        t_invalid = properties.get('t_invalid')
        t_created = properties.get('t_created')
        t_expired = properties.get('t_expired')
        
        # Parse timestamps if strings
        if isinstance(t_valid, str):
            t_valid = datetime.fromisoformat(t_valid.replace('Z', '+00:00'))
        if isinstance(t_invalid, str):
            t_invalid = datetime.fromisoformat(t_invalid.replace('Z', '+00:00'))
        if isinstance(t_created, str):
            t_created = datetime.fromisoformat(t_created.replace('Z', '+00:00'))
        if isinstance(t_expired, str):
            t_expired = datetime.fromisoformat(t_expired.replace('Z', '+00:00'))
        
        # Check system timeline (was it recorded before as_of?)
        if t_created and t_created > as_of:
            return False
        if t_expired and t_expired <= as_of:
            return False
        
        # Check real-world timeline
        if t_valid and t_valid > as_of:
            return False
        if t_invalid and t_invalid <= as_of:
            return False
        
        return True


class Neo4jGraphStore(GraphStore):
    """
    Neo4j implementation for production deployments.
    """
    
    def __init__(self, uri: str, user: str, password: str, database: str = "neo4j"):
        from neo4j import AsyncGraphDatabase
        
        self.driver = AsyncGraphDatabase.driver(uri, auth=(user, password))
        self.database = database
    
    async def create_node(
        self,
        labels: List[str],
        properties: Dict[str, Any],
        node_id: Optional[str] = None
    ) -> str:
        label_str = ':'.join(labels)
        
        if node_id:
            properties['_id'] = node_id
        
        if 't_created' not in properties:
            properties['t_created'] = datetime.utcnow().isoformat()
        
        query = f"""
        CREATE (n:{label_str} $props)
        RETURN elementId(n) as id
        """
        
        async with self.driver.session(database=self.database) as session:
            result = await session.run(query, {'props': properties})
            record = await result.single()
            return record['id']
    
    async def create_edge(
        self,
        edge_type: str,
        source_id: str,
        target_id: str,
        properties: Dict[str, Any]
    ) -> str:
        if 't_created' not in properties:
            properties['t_created'] = datetime.utcnow().isoformat()
        
        query = f"""
        MATCH (a) WHERE elementId(a) = $source_id OR a._id = $source_id
        MATCH (b) WHERE elementId(b) = $target_id OR b._id = $target_id
        CREATE (a)-[r:{edge_type} $props]->(b)
        RETURN elementId(r) as id
        """
        
        async with self.driver.session(database=self.database) as session:
            result = await session.run(query, {
                'source_id': source_id,
                'target_id': target_id,
                'props': properties
            })
            record = await result.single()
            return record['id']
    
    async def get_node(
        self,
        node_id: str,
        as_of: Optional[datetime] = None
    ) -> Optional[NodeData]:
        query = """
        MATCH (n) WHERE elementId(n) = $node_id OR n._id = $node_id
        """
        
        if as_of:
            query += """
            AND (n.t_created IS NULL OR datetime(n.t_created) <= $as_of)
            AND (n.t_expired IS NULL OR datetime(n.t_expired) > $as_of)
            AND (n.t_valid IS NULL OR datetime(n.t_valid) <= $as_of)
            AND (n.t_invalid IS NULL OR datetime(n.t_invalid) > $as_of)
            """
        
        query += "RETURN n, labels(n) as labels"
        
        async with self.driver.session(database=self.database) as session:
            result = await session.run(query, {
                'node_id': node_id,
                'as_of': as_of.isoformat() if as_of else None
            })
            record = await result.single()
            
            if record:
                return NodeData(
                    id=node_id,
                    labels=record['labels'],
                    properties=dict(record['n'])
                )
            return None
    
    async def query(
        self,
        cypher: str,
        params: Dict[str, Any],
        as_of: Optional[datetime] = None
    ) -> QueryResult:
        if as_of:
            params['_as_of'] = as_of.isoformat()
        
        async with self.driver.session(database=self.database) as session:
            result = await session.run(cypher, params)
            records = await result.data()
            
            # Parse results into nodes and edges
            # (simplified - production would need proper parsing)
            return QueryResult(
                nodes=[],
                edges=[],
                raw=records
            )
    
    async def traverse(
        self,
        start_id: str,
        edge_types: List[str],
        max_depth: int = 3,
        as_of: Optional[datetime] = None
    ) -> QueryResult:
        edge_pattern = '|'.join(edge_types) if edge_types else ''
        rel_pattern = f"[*1..{max_depth}]" if not edge_pattern else f"[:{edge_pattern}*1..{max_depth}]"
        
        query = f"""
        MATCH (start) WHERE elementId(start) = $start_id OR start._id = $start_id
        MATCH path = (start)-{rel_pattern}-(connected)
        """
        
        if as_of:
            query += """
            WHERE ALL(n IN nodes(path) WHERE 
                (n.t_created IS NULL OR datetime(n.t_created) <= $as_of) AND
                (n.t_expired IS NULL OR datetime(n.t_expired) > $as_of))
            AND ALL(r IN relationships(path) WHERE
                (r.t_created IS NULL OR datetime(r.t_created) <= $as_of) AND
                (r.t_expired IS NULL OR datetime(r.t_expired) > $as_of))
            """
        
        query += """
        RETURN nodes(path) as nodes, relationships(path) as rels
        LIMIT 100
        """
        
        async with self.driver.session(database=self.database) as session:
            result = await session.run(query, {
                'start_id': start_id,
                'as_of': as_of.isoformat() if as_of else None
            })
            records = await result.data()
            
            all_nodes = {}
            all_edges = {}
            
            for record in records:
                for node in record.get('nodes', []):
                    nid = str(node.element_id)
                    if nid not in all_nodes:
                        all_nodes[nid] = NodeData(
                            id=nid,
                            labels=list(node.labels),
                            properties=dict(node)
                        )
                
                for rel in record.get('rels', []):
                    eid = str(rel.element_id)
                    if eid not in all_edges:
                        all_edges[eid] = EdgeData(
                            id=eid,
                            type=rel.type,
                            source_id=str(rel.start_node.element_id),
                            target_id=str(rel.end_node.element_id),
                            properties=dict(rel)
                        )
            
            return QueryResult(
                nodes=list(all_nodes.values()),
                edges=list(all_edges.values()),
                raw=records
            )
    
    async def close(self):
        await self.driver.close()
```

---

## Performance Envelope & SLOs

### Target Performance Metrics

| Operation | P50 Target | P95 Target | P99 Target | Hard Limit |
|-----------|------------|------------|------------|------------|
| Session build (no trace) | 100ms | 200ms | 500ms | 1s |
| Session build (with trace) | 150ms | 350ms | 700ms | 1.5s |
| as_of query (cached) | 20ms | 50ms | 100ms | 200ms |
| as_of query (cold) | 100ms | 200ms | 400ms | 800ms |
| Explanation retrieval (cached) | 10ms | 30ms | 50ms | 100ms |
| Explanation generation (async) | 500ms | 1s | 2s | 5s |
| Blast radius (4-hop) | 200ms | 500ms | 1s | 2s |
| Ingestion health check | 5ms | 10ms | 20ms | 50ms |

### Traversal Depth Limits

| Context | Max Depth | Rationale |
|---------|-----------|-----------|
| Real-time triage (T1) | 2 hops | Sub-100ms response required |
| Investigation (T2) | 4 hops | Balance depth vs latency |
| Async analysis | 6 hops | Batch processing acceptable |
| Blast radius | 4 hops | Prevent runaway traversals |

### Caching Strategy

```python
# ============================================================
# Cache configuration for decision trace queries
# ============================================================

CACHE_CONFIG = {
    # Explanation cache (most frequently accessed)
    'explanation': {
        'ttl_seconds': 86400 * 7,  # 7 days
        'max_entries': 100000,
        'eviction': 'lru'
    },
    
    # Session trace cache
    'session_trace': {
        'ttl_seconds': 3600,  # 1 hour (sessions are relatively static)
        'max_entries': 10000,
        'eviction': 'lru'
    },
    
    # as_of query results
    'as_of_query': {
        'ttl_seconds': 300,  # 5 minutes (historical data doesn't change)
        'max_entries': 5000,
        'eviction': 'lru',
        'key_pattern': '{query_hash}:{as_of_timestamp}'
    },
    
    # Ingestion health (very short TTL, frequently updated)
    'ingestion_health': {
        'ttl_seconds': 10,
        'max_entries': 100,
        'eviction': 'ttl'
    }
}
```

---

## Pipeline Integration Points

### Phase-by-Phase Instrumentation

```python
# ============================================================
# Pipeline integration hooks
# ============================================================

from dataclasses import dataclass
from typing import Optional, List, Dict
from datetime import datetime

@dataclass
class PipelineContext:
    """Context passed through pipeline phases."""
    session_id: str
    correlation_window: tuple  # (start, end)
    decisions: List[str] = None  # Decision IDs created
    evidence: List[str] = None   # Evidence IDs created
    anomalies: List[dict] = None # Detected anomalies
    
    def __post_init__(self):
        self.decisions = self.decisions or []
        self.evidence = self.evidence or []
        self.anomalies = self.anomalies or []

class DecisionTraceInstrumentation:
    """
    Instrumentation hooks for decision trace generation.
    
    Integrates with existing JanuSec pipeline without breaking
    current functionality.
    """
    
    def __init__(self, graph_store: 'GraphStore', anomaly_detector: 'IngestionAnomalyDetector'):
        self.graph = graph_store
        self.anomaly_detector = anomaly_detector
    
    # ============================================================
    # PHASE 1: INGEST
    # ============================================================
    
    async def on_event_ingested(
        self,
        raw_event: dict,
        source_system: str,
        connector: str,
        ctx: PipelineContext
    ) -> str:
        """
        Called when raw event is ingested.
        Creates Evidence node with bi-temporal stamps.
        """
        # Extract event timestamp (t_valid)
        t_valid = self._extract_event_time(raw_event, source_system)
        t_created = datetime.utcnow()
        
        # Check for ingestion anomalies
        anomalies = self.anomaly_detector.process_evidence(
            evidence_id="pending",
            source_system=source_system,
            connector=connector,
            t_valid=t_valid,
            t_created=t_created
        )
        ctx.anomalies.extend([a.__dict__ for a in anomalies])
        
        # Create Evidence node
        evidence_id = await self.graph.create_node(
            labels=['Evidence'],
            properties={
                'evidence_type': self._classify_event_type(raw_event, source_system),
                'source_system': source_system,
                'connector': connector,
                'raw_event_id': raw_event.get('id', raw_event.get('event_id')),
                't_valid': t_valid.isoformat(),
                't_invalid': None,
                't_created': t_created.isoformat(),
                't_expired': None,
                'ingestion_delta_ms': (t_created - t_valid).total_seconds() * 1000
            }
        )
        
        ctx.evidence.append(evidence_id)
        return evidence_id
    
    # ============================================================
    # PHASE 2: NORMALIZE / MAP
    # ============================================================
    
    async def on_event_normalized(
        self,
        evidence_id: str,
        normalized_event: dict,
        mapping_stats: dict,
        entity_resolutions: List[dict],
        ctx: PipelineContext
    ) -> None:
        """
        Called after normalization.
        Updates Evidence with mapping semantics and creates Entity links.
        """
        # Update Evidence with mapping quality
        await self.graph.query(
            """
            MATCH (e:Evidence {_id: $evidence_id})
            SET e.fields_present = $fields,
                e.high_value_fields_count = $hv_count,
                e.supporting_fields_count = $sf_count,
                e.mapping_quality_score = $quality
            """,
            {
                'evidence_id': evidence_id,
                'fields': mapping_stats.get('fields_present', []),
                'hv_count': mapping_stats.get('high_value_count', 0),
                'sf_count': mapping_stats.get('supporting_count', 0),
                'quality': mapping_stats.get('quality_score', 0.0)
            }
        )
        
        # Create/link Entity nodes
        for resolution in entity_resolutions:
            await self._link_evidence_to_entity(evidence_id, resolution)
    
    async def _link_evidence_to_entity(
        self,
        evidence_id: str,
        resolution: dict
    ) -> None:
        """Create or link to canonical entity."""
        entity_type = resolution['entity_type']  # 'Identity', 'Device', etc.
        canonical_id = resolution['canonical_id']
        
        # Ensure entity exists
        existing = await self.graph.get_node(canonical_id)
        if not existing:
            await self.graph.create_node(
                labels=[entity_type],
                properties={
                    'canonical_id': canonical_id,
                    'aliases': resolution.get('aliases', []),
                    't_created': datetime.utcnow().isoformat()
                },
                node_id=canonical_id
            )
        
        # Create OBSERVED_ON relationship
        await self.graph.create_edge(
            edge_type='OBSERVED_ON',
            source_id=evidence_id,
            target_id=canonical_id,
            properties={
                'observation_type': resolution.get('role', 'unknown'),
                'field_path': resolution.get('source_field'),
                'confidence': resolution.get('stitch_quality', 1.0)
            }
        )
    
    # ============================================================
    # PHASE 3: CORRELATE
    # ============================================================
    
    async def on_correlation_step(
        self,
        step_name: str,
        evidence_ids: List[str],
        correlation_result: dict,
        ctx: PipelineContext
    ) -> str:
        """
        Called for each correlation step.
        Creates Decision node and links consumed Evidence.
        """
        decision_id = await self.graph.create_node(
            labels=['Decision'],
            properties={
                'decision_id': f"{ctx.session_id}:{step_name}:{len(ctx.decisions)}",
                'session_id': ctx.session_id,
                'decision_type': 'correlation',
                'correlation_step': step_name,
                'confidence': correlation_result.get('confidence', 0.0),
                'explainable_factors': correlation_result.get('factors', []),
                't_valid': datetime.utcnow().isoformat(),
                't_created': datetime.utcnow().isoformat(),
                
                # NIST AI RMF fields
                'intended_purpose': 'security_triage',
                'deployment_context': 'soc_automation'
            }
        )
        
        # Link to session
        await self.graph.create_edge(
            edge_type='CONTAINS',
            source_id=ctx.session_id,
            target_id=decision_id,
            properties={'order': len(ctx.decisions)}
        )
        
        # Link consumed evidence
        for eid in evidence_ids:
            await self.graph.create_edge(
                edge_type='CONSUMES',
                source_id=decision_id,
                target_id=eid,
                properties={
                    'relevance_score': correlation_result.get('evidence_relevance', {}).get(eid, 1.0)
                }
            )
        
        ctx.decisions.append(decision_id)
        return decision_id
    
    # ============================================================
    # PHASE 4: SCORE / GOVERN
    # ============================================================
    
    async def on_policy_evaluated(
        self,
        decision_id: str,
        policy_result: dict,
        exceptions_applied: List[dict],
        ctx: PipelineContext
    ) -> str:
        """
        Called when policies are evaluated.
        Creates PolicyEval and Exception nodes.
        """
        policy_eval_id = await self.graph.create_node(
            labels=['PolicyEval'],
            properties={
                'policy_id': policy_result['policy_id'],
                'policy_version': policy_result.get('policy_version', '1.0'),
                'policy_name': policy_result.get('policy_name'),
                'scoring_config_version': policy_result.get('scoring_config_version'),
                'base_score': policy_result.get('base_score', 0.0),
                'context_multipliers': policy_result.get('multipliers', {}),
                'final_score': policy_result.get('final_score', 0.0),
                't_valid': datetime.utcnow().isoformat(),
                't_created': datetime.utcnow().isoformat()
            }
        )
        
        # Link to decision
        await self.graph.create_edge(
            edge_type='EVALUATES',
            source_id=decision_id,
            target_id=policy_eval_id,
            properties={}
        )
        
        # Create Exception nodes if any were applied
        for exc in exceptions_applied:
            exception_id = await self.graph.create_node(
                labels=['Exception'],
                properties={
                    'exception_type': exc['type'],
                    'justification': exc.get('justification'),
                    'approved_by': exc.get('approved_by'),
                    't_valid': exc.get('effective_start'),
                    't_invalid': exc.get('effective_end'),
                    't_created': datetime.utcnow().isoformat()
                }
            )
            
            await self.graph.create_edge(
                edge_type='INVOKED_EXCEPTION',
                source_id=policy_eval_id,
                target_id=exception_id,
                properties={'match_reason': exc.get('match_reason')}
            )
        
        return policy_eval_id
    
    # ============================================================
    # PHASE 5: OUTCOME
    # ============================================================
    
    async def on_outcome_produced(
        self,
        decision_id: str,
        outcome: dict,
        ctx: PipelineContext
    ) -> str:
        """
        Called when final outcome is produced.
        Creates Outcome node.
        """
        outcome_id = await self.graph.create_node(
            labels=['Outcome'],
            properties={
                'action_type': outcome['action_type'],
                'severity': outcome.get('severity'),
                'incident_id': outcome.get('incident_id'),
                'recommendations': outcome.get('recommendations', []),
                't_valid': datetime.utcnow().isoformat(),
                't_created': datetime.utcnow().isoformat(),
                'ttl_seconds': outcome.get('ttl', 86400 * 30)  # 30 days default
            }
        )
        
        await self.graph.create_edge(
            edge_type='PRODUCES',
            source_id=decision_id,
            target_id=outcome_id,
            properties={}
        )
        
        return outcome_id
    
    # ============================================================
    # ASYNC: EXPLANATION GENERATION
    # ============================================================
    
    async def generate_explanations_async(
        self,
        decision_ids: List[str],
        explanation_generator: 'ExplanationGenerator'
    ) -> None:
        """
        Async task to generate and cache explanations.
        Called after session build completes.
        """
        for decision_id in decision_ids:
            try:
                # Generate triage explanation
                triage_explanation = await explanation_generator.generate_triage_explanation(
                    decision_id
                )
                if triage_explanation:
                    await cache_explanation(self.graph, decision_id, triage_explanation)
                
                # Generate blast radius (for high-severity only)
                decision = await self.graph.get_node(decision_id)
                if decision and decision.properties.get('severity') in ['high', 'critical']:
                    blast_explanation = await explanation_generator.generate_blast_radius_explanation(
                        decision_id
                    )
                    if blast_explanation:
                        await cache_explanation(self.graph, decision_id, blast_explanation)
            
            except Exception as e:
                # Log but don't fail - explanations are non-critical
                print(f"Failed to generate explanation for {decision_id}: {e}")
    
    # ============================================================
    # HELPERS
    # ============================================================
    
    def _extract_event_time(self, raw_event: dict, source_system: str) -> datetime:
        """Extract event timestamp based on source format."""
        # Source-specific timestamp field mapping
        timestamp_fields = {
            'crowdstrike': ['timestamp', '@timestamp', 'ProcessStartTime'],
            'sentinel': ['TimeGenerated', 'timestamp'],
            'okta': ['published', 'timestamp'],
            'aws_cloudtrail': ['eventTime'],
            'default': ['timestamp', '@timestamp', 'time', 'datetime', 'created_at']
        }
        
        fields = timestamp_fields.get(source_system.lower(), timestamp_fields['default'])
        
        for field in fields:
            if field in raw_event:
                ts = raw_event[field]
                if isinstance(ts, datetime):
                    return ts
                if isinstance(ts, str):
                    return datetime.fromisoformat(ts.replace('Z', '+00:00'))
                if isinstance(ts, (int, float)):
                    # Assume epoch milliseconds
                    return datetime.fromtimestamp(ts / 1000)
        
        # Fallback to now (shouldn't happen in production)
        return datetime.utcnow()
    
    def _classify_event_type(self, raw_event: dict, source_system: str) -> str:
        """Classify event type for Evidence node."""
        # Simplified classification
        if 'alert' in str(raw_event).lower():
            return 'alert'
        if 'authentication' in str(raw_event).lower() or 'login' in str(raw_event).lower():
            return 'authentication'
        if 'process' in str(raw_event).lower():
            return 'process_execution'
        if 'network' in str(raw_event).lower() or 'connection' in str(raw_event).lower():
            return 'network_connection'
        if 'file' in str(raw_event).lower():
            return 'file_activity'
        return 'telemetry'
```

---

## Tiered LLM Summaries

### Tier 1: Analyst Triage Card

```python
# ============================================================
# T1 Summary Generation
# ============================================================

TIER1_PROMPT = """
You are a security analyst assistant. Generate a concise triage summary.

DECISION CONTEXT:
- Severity: {severity}
- Confidence: {confidence}
- Factors: {factors}

EVIDENCE SUMMARY:
{evidence_summary}

POLICY MATCHES:
{policy_summary}

OUTCOME:
{outcome_summary}

Generate a 2-3 sentence summary for SOC analyst triage. Include:
1. What happened (actor, action, target)
2. Why it's suspicious (key factors)
3. Recommended next step

Keep it under 100 words. Be direct and actionable.
"""

async def generate_tier1_summary(
    decision_id: str,
    graph_client,
    llm_client
) -> str:
    """Generate T1 analyst triage summary."""
    
    # Fetch decision context
    query = """
    MATCH (d:Decision {decision_id: $decision_id})
    OPTIONAL MATCH (d)-[:CONSUMES]->(e:Evidence)-[:OBSERVED_ON]->(entity)
    OPTIONAL MATCH (d)-[:EVALUATES]->(p:PolicyEval)
    OPTIONAL MATCH (d)-[:PRODUCES]->(o:Outcome)
    RETURN d, 
           collect(DISTINCT {type: e.evidence_type, source: e.source_system, entity: entity.canonical_id}) as evidence,
           collect(DISTINCT p.policy_name) as policies,
           o
    """
    
    result = await graph_client.query(query, {'decision_id': decision_id})
    
    if not result.raw:
        return "Insufficient context for summary generation."
    
    record = result.raw[0]
    decision = record['d']
    evidence = record['evidence']
    policies = record['policies']
    outcome = record['o']
    
    # Format prompt
    evidence_summary = "\n".join([
        f"- {e['type']} from {e['source']}: {e['entity']}"
        for e in evidence if e['type']
    ][:5])  # Limit to top 5
    
    policy_summary = ", ".join([p for p in policies if p][:3])
    
    outcome_summary = f"{outcome['action_type']}: severity={outcome.get('severity', 'unknown')}" if outcome else "No outcome recorded"
    
    prompt = TIER1_PROMPT.format(
        severity=decision.get('severity', 'Medium'),
        confidence=decision.get('confidence', 0.0),
        factors=decision.get('explainable_factors', []),
        evidence_summary=evidence_summary or "No evidence linked",
        policy_summary=policy_summary or "No policies matched",
        outcome_summary=outcome_summary
    )
    
    response = await llm_client.complete(prompt, max_tokens=200)
    return response.strip()
```

### Tier 2: Investigation Deep Dive

```python
# ============================================================
# T2 GraphRAG-Lite Summary
# ============================================================

TIER2_GLOBAL_PROMPT = """
You are analyzing a security incident for investigation.

SESSION OVERVIEW:
{session_summary}

COMMUNITY THEMES:
{community_descriptions}

Provide a comprehensive analysis including:
1. Attack narrative (what happened chronologically)
2. Affected scope (entities and systems involved)
3. Key indicators and TTPs observed
4. Confidence assessment and gaps
5. Recommended investigation steps

Be thorough but structured. Use bullet points for clarity.
"""

async def generate_tier2_summary(
    session_id: str,
    graph_client,
    llm_client,
    include_blast_radius: bool = True
) -> str:
    """
    Generate T2 investigation summary using GraphRAG-lite approach.
    
    Uses community summarization for global context + local
    entity neighborhood for specific details.
    """
    
    # 1. Get session-level summary (global)
    session_query = """
    MATCH (s:Session {session_id: $session_id})-[:CONTAINS]->(d:Decision)
    OPTIONAL MATCH (d)-[:CONSUMES]->(e:Evidence)
    OPTIONAL MATCH (d)-[:PRODUCES]->(o:Outcome)
    RETURN s,
           count(DISTINCT d) as decision_count,
           count(DISTINCT e) as evidence_count,
           collect(DISTINCT d.severity) as severities,
           collect(DISTINCT o.action_type) as outcomes
    """
    
    session_result = await graph_client.query(session_query, {'session_id': session_id})
    
    # 2. Get community-level themes (simplified - production would use Leiden clustering)
    community_query = """
    MATCH (s:Session {session_id: $session_id})-[:CONTAINS]->(d:Decision)
           -[:CONSUMES]->(e:Evidence)-[:OBSERVED_ON]->(entity)
    WITH labels(entity)[0] as entity_type, collect(DISTINCT entity.canonical_id) as entities
    RETURN entity_type, entities, size(entities) as count
    ORDER BY count DESC
    """
    
    community_result = await graph_client.query(community_query, {'session_id': session_id})
    
    # 3. Get blast radius if requested
    blast_summary = ""
    if include_blast_radius:
        blast_query = """
        MATCH (s:Session {session_id: $session_id})-[:CONTAINS]->(d:Decision)
               -[:CONSUMES]->(e:Evidence)-[:OBSERVED_ON]->(start)
        MATCH path = (start)-[*1..3]-(connected)
        WHERE connected:Identity OR connected:Device OR connected:CloudResource
        RETURN count(DISTINCT connected) as affected_count,
               collect(DISTINCT labels(connected)[0]) as affected_types
        """
        blast_result = await graph_client.query(blast_query, {'session_id': session_id})
        if blast_result.raw:
            blast_data = blast_result.raw[0]
            blast_summary = f"Blast radius: {blast_data['affected_count']} entities ({', '.join(blast_data['affected_types'])})"
    
    # Format summaries
    session_data = session_result.raw[0] if session_result.raw else {}
    session_summary = f"""
    - Decisions: {session_data.get('decision_count', 0)}
    - Evidence items: {session_data.get('evidence_count', 0)}
    - Severities: {', '.join(set(session_data.get('severities', [])))}
    - Outcomes: {', '.join(set(session_data.get('outcomes', [])))}
    {blast_summary}
    """
    
    community_descriptions = "\n".join([
        f"- {r['entity_type']}: {r['count']} entities involved"
        for r in community_result.raw
    ]) if community_result.raw else "No community analysis available"
    
    prompt = TIER2_GLOBAL_PROMPT.format(
        session_summary=session_summary,
        community_descriptions=community_descriptions
    )
    
    response = await llm_client.complete(prompt, max_tokens=800)
    return response.strip()
```

---

## Cyber Risk Quantification

### Risk Model Integration

```python
# ============================================================
# Risk quantification from decision traces
# ============================================================

from dataclasses import dataclass
from typing import Dict, List
from enum import Enum

class AssetCriticality(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class RiskQuantification:
    """Risk quantification output from decision traces."""
    expected_loss_band: tuple  # (min, max) in dollars
    likelihood: float  # 0.0 - 1.0
    impact_score: float  # Normalized 0.0 - 1.0
    confidence: float  # Confidence in estimate
    
    # Breakdown
    blind_spot_risk: float
    detection_precision: float
    control_effectiveness: float
    
    # Factors
    contributing_factors: List[dict]

async def quantify_risk_from_traces(
    session_id: str,
    graph_client,
    asset_values: Dict[str, float],  # canonical_id -> dollar value
    detection_precision: float = 0.92  # JanuSec's claimed precision
) -> RiskQuantification:
    """
    Quantify cyber risk from decision trace data.
    
    Uses:
    - Historical decision frequencies for likelihood
    - Asset criticality and blast radius for impact
    - Ingestion health for blind spot adjustment
    - Detection precision for uncertainty bounds
    """
    
    # 1. Calculate likelihood from historical frequencies
    frequency_query = """
    MATCH (d:Decision)
    WHERE d.t_valid >= datetime() - duration('P30D')
    WITH d.severity as severity, count(*) as count
    RETURN severity, count
    """
    
    frequency_result = await graph_client.query(frequency_query, {})
    
    # Estimate base likelihood per severity
    severity_likelihoods = {
        'critical': 0.05,
        'high': 0.15,
        'medium': 0.40,
        'low': 0.60
    }
    
    # 2. Calculate impact from affected assets
    impact_query = """
    MATCH (s:Session {session_id: $session_id})-[:CONTAINS]->(d:Decision)
           -[:CONSUMES]->(e:Evidence)-[:OBSERVED_ON]->(entity)
    RETURN collect(DISTINCT entity.canonical_id) as affected_entities,
           max(CASE d.severity 
               WHEN 'critical' THEN 4 
               WHEN 'high' THEN 3 
               WHEN 'medium' THEN 2 
               ELSE 1 END) as max_severity
    """
    
    impact_result = await graph_client.query(impact_query, {'session_id': session_id})
    impact_data = impact_result.raw[0] if impact_result.raw else {}
    
    affected_entities = impact_data.get('affected_entities', [])
    total_asset_value = sum(
        asset_values.get(eid, 10000)  # Default $10k if unknown
        for eid in affected_entities
    )
    
    max_severity = impact_data.get('max_severity', 2)
    
    # 3. Get blind spot risk from ingestion health
    blind_spot_query = """
    MATCH (s:Session {session_id: $session_id})-[:AFFECTED_BY_GAP]->(g:IngestionGap)
    RETURN count(g) as gap_count,
           sum(g.estimated_missing_events) as missing_events,
           max(g.deviation_sigma) as max_deviation
    """
    
    blind_spot_result = await graph_client.query(blind_spot_query, {'session_id': session_id})
    blind_spot_data = blind_spot_result.raw[0] if blind_spot_result.raw else {}
    
    gap_count = blind_spot_data.get('gap_count', 0)
    blind_spot_risk = min(gap_count * 0.1, 0.5)  # Cap at 50%
    
    # 4. Calculate expected loss
    severity_map = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low'}
    base_likelihood = severity_likelihoods.get(severity_map.get(max_severity, 'medium'), 0.3)
    
    # Adjust for detection precision and blind spots
    adjusted_likelihood = base_likelihood * (1 + blind_spot_risk) / detection_precision
    
    # Impact as fraction of asset value at risk
    impact_multipliers = {4: 0.8, 3: 0.5, 2: 0.2, 1: 0.05}
    impact_fraction = impact_multipliers.get(max_severity, 0.2)
    
    expected_loss = adjusted_likelihood * total_asset_value * impact_fraction
    
    # Uncertainty bounds (wider with lower confidence)
    confidence = detection_precision * (1 - blind_spot_risk)
    uncertainty = 1 - confidence
    
    loss_min = expected_loss * (1 - uncertainty)
    loss_max = expected_loss * (1 + uncertainty * 2)
    
    # Control effectiveness from policy eval coverage
    control_query = """
    MATCH (s:Session {session_id: $session_id})-[:CONTAINS]->(d:Decision)
    OPTIONAL MATCH (d)-[:EVALUATES]->(p:PolicyEval)
    WITH count(DISTINCT d) as decisions, count(DISTINCT p) as policy_evals
    RETURN CASE WHEN decisions > 0 
                THEN toFloat(policy_evals) / decisions 
                ELSE 0.0 END as control_coverage
    """
    
    control_result = await graph_client.query(control_query, {'session_id': session_id})
    control_coverage = control_result.raw[0].get('control_coverage', 0.0) if control_result.raw else 0.0
    
    return RiskQuantification(
        expected_loss_band=(loss_min, loss_max),
        likelihood=adjusted_likelihood,
        impact_score=impact_fraction,
        confidence=confidence,
        blind_spot_risk=blind_spot_risk,
        detection_precision=detection_precision,
        control_effectiveness=control_coverage,
        contributing_factors=[
            {'name': 'asset_value', 'value': total_asset_value},
            {'name': 'affected_entities', 'value': len(affected_entities)},
            {'name': 'max_severity', 'value': max_severity},
            {'name': 'ingestion_gaps', 'value': gap_count}
        ]
    )
```

---

## Compliance Framework Mapping

### Audit Schema

```python
# ============================================================
# Compliance audit schema (14 fields for EU AI Act readiness)
# ============================================================

AUDIT_SCHEMA = {
    # Temporal fields
    'timestamp': 'datetime',           # When audit record created
    'event_timestamp': 'datetime',     # t_valid of audited event
    'system_timestamp': 'datetime',    # t_created of audited event
    
    # Classification
    'query_type': 'string',            # 'read' | 'write' | 'traverse' | 'explain'
    'risk_level': 'string',            # 'low' | 'medium' | 'high' | 'critical'
    'compliance_frameworks': 'array',  # ['ISO42001', 'EUAIACT', 'NIST_AIRMF']
    
    # Access details
    'user_id': 'string',               # Who performed the query
    'session_id': 'string',            # Which session was accessed
    'decision_ids': 'array',           # Which decisions were accessed
    
    # Graph traversal details (EU AI Act Art. 12)
    'traversal_paths': 'array',        # Relationship paths traversed
    'nodes_accessed': 'array',         # Node IDs accessed
    'depth': 'integer',                # Maximum traversal depth
    
    # Explainability (EU AI Act Art. 14)
    'explanation_generated': 'boolean',
    'explanation_text': 'string',      # Natural language explanation
    'explanation_confidence': 'float'
}

# Audit logging implementation
async def log_audit_event(
    graph_client,
    event_type: str,
    user_id: str,
    session_id: str,
    details: dict
) -> str:
    """Log compliance audit event."""
    
    audit_id = await graph_client.create_node(
        labels=['AuditLog'],
        properties={
            'audit_id': f"audit_{datetime.utcnow().timestamp()}",
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'session_id': session_id,
            'query_type': details.get('query_type', 'unknown'),
            'risk_level': details.get('risk_level', 'low'),
            'compliance_frameworks': details.get('frameworks', []),
            'traversal_paths': details.get('paths', []),
            'nodes_accessed': details.get('nodes', []),
            'depth': details.get('depth', 0),
            'explanation_generated': details.get('explanation_generated', False),
            'explanation_text': details.get('explanation_text'),
            'explanation_confidence': details.get('explanation_confidence', 0.0)
        }
    )
    
    return audit_id
```

### Framework Control Mapping

| Control | ISO 42001 | ISO 27001 | NIST AI RMF | EU AI Act |
|---------|-----------|-----------|-------------|-----------|
| **Decision logging** | A.6.2.6 | A.8.15 | MAP 1.1 | Art. 12(1) |
| **Bi-temporal audit** | A.6.2.7 | A.8.15 | MEASURE 2.3 | Art. 12(2) |
| **Explanation generation** | A.6.2.8 | - | MAP 1.6 | Art. 14(4) |
| **Access control** | A.6.2.4 | A.8.3 | GOVERN 1.4 | Art. 9(4) |
| **Data governance** | A.6.2.1 | A.8.10 | MAP 1.2 | Art. 10 |
| **Risk assessment** | A.6.1.2 | A.8.8 | MEASURE 1.1 | Art. 9(2) |
| **Human oversight** | A.6.2.9 | - | MANAGE 4.1 | Art. 14 |
| **Version control** | A.6.2.5 | A.8.32 | MANAGE 2.4 | Art. 12(3) |

---

## API Specifications

### Session Build with Trace

```yaml
# OpenAPI 3.0 Specification (excerpt)

paths:
  /api/v1/graph/session/build:
    post:
      summary: Build correlation session with decision traces
      parameters:
        - name: as_of
          in: query
          schema:
            type: string
            format: date-time
          description: Point-in-time for bi-temporal query
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/SessionBuildRequest'
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SessionBuildResponse'

components:
  schemas:
    SessionBuildRequest:
      type: object
      required:
        - events
      properties:
        events:
          type: array
          items:
            $ref: '#/components/schemas/RawEvent'
        correlation_window:
          type: object
          properties:
            start:
              type: string
              format: date-time
            end:
              type: string
              format: date-time
        include_decision_trace:
          type: boolean
          default: true
        include_explanations:
          type: boolean
          default: false
          description: Generate explanations synchronously (slower)
    
    SessionBuildResponse:
      type: object
      properties:
        session_id:
          type: string
        status:
          type: string
          enum: [active, completed, error]
        correlation_results:
          $ref: '#/components/schemas/CorrelationResults'
        decision_trace:
          $ref: '#/components/schemas/DecisionTrace'
        ingestion_health:
          $ref: '#/components/schemas/IngestionHealth'
    
    DecisionTrace:
      type: object
      properties:
        decisions:
          type: array
          items:
            $ref: '#/components/schemas/DecisionSummary'
        evidence:
          type: array
          items:
            $ref: '#/components/schemas/EvidenceSummary'
        policy_evals:
          type: array
          items:
            $ref: '#/components/schemas/PolicyEvalSummary'
        outcomes:
          type: array
          items:
            $ref: '#/components/schemas/OutcomeSummary'
        precedents:
          type: array
          items:
            $ref: '#/components/schemas/PrecedentLink'
        temporal_coverage:
          type: object
          properties:
            earliest_t_valid:
              type: string
              format: date-time
            latest_t_valid:
              type: string
              format: date-time
            ingestion_lag_p50_ms:
              type: number
            ingestion_lag_p95_ms:
              type: number
    
    DecisionSummary:
      type: object
      properties:
        decision_id:
          type: string
        decision_type:
          type: string
        severity:
          type: string
        confidence:
          type: number
        explainable_factors:
          type: array
          items:
            type: object
        t_valid:
          type: string
          format: date-time
        t_created:
          type: string
          format: date-time
        intended_purpose:
          type: string
        deployment_context:
          type: string
    
    IngestionHealth:
      type: object
      properties:
        overall_status:
          type: string
          enum: [healthy, degraded, critical, unknown]
        blind_spot_risk:
          type: number
          minimum: 0
          maximum: 1
        domains:
          type: object
          additionalProperties:
            $ref: '#/components/schemas/DomainHealth'
        anomalies_detected:
          type: array
          items:
            $ref: '#/components/schemas/IngestionAnomaly'
```

---

## Security Considerations

### Threat Model

| Threat | Attack Vector | Mitigation |
|--------|--------------|------------|
| **Graph poisoning** | Malicious evidence injection | Input validation, provenance tracking, anomaly detection |
| **Inference attack** | Deriving sensitive info from graph structure | Property-level access control, differential privacy |
| **Traversal DoS** | Unbounded queries | Depth limits, query timeouts, rate limiting |
| **Explanation manipulation** | Injecting misleading explanations | Explanation signing, audit logging |
| **Temporal replay** | Injecting old events as new | Clock skew detection, freshness validation |

### Security Controls

```python
# ============================================================
# Security middleware for graph queries
# ============================================================

class GraphSecurityMiddleware:
    """Security controls for context graph access."""
    
    MAX_TRAVERSAL_DEPTH = 6
    MAX_NODES_PER_QUERY = 1000
    RATE_LIMIT_QUERIES_PER_MINUTE = 100
    
    def __init__(self, graph_client, audit_logger):
        self.graph = graph_client
        self.audit = audit_logger
        self._rate_limiter = {}
    
    async def execute_query(
        self,
        user_id: str,
        query: str,
        params: dict,
        required_permissions: List[str]
    ) -> QueryResult:
        """Execute query with security controls."""
        
        # 1. Rate limiting
        if not self._check_rate_limit(user_id):
            raise RateLimitExceeded(f"User {user_id} exceeded query rate limit")
        
        # 2. Query analysis
        query_analysis = self._analyze_query(query, params)
        
        # 3. Depth limit enforcement
        if query_analysis['max_depth'] > self.MAX_TRAVERSAL_DEPTH:
            raise QueryDepthExceeded(
                f"Query depth {query_analysis['max_depth']} exceeds limit {self.MAX_TRAVERSAL_DEPTH}"
            )
        
        # 4. Permission check (simplified - production would use proper RBAC)
        if not self._check_permissions(user_id, required_permissions):
            await self.audit.log_audit_event(
                self.graph,
                'permission_denied',
                user_id,
                params.get('session_id', 'unknown'),
                {'query': query[:100], 'required': required_permissions}
            )
            raise PermissionDenied(f"User {user_id} lacks required permissions")
        
        # 5. Execute with timeout
        try:
            result = await asyncio.wait_for(
                self.graph.query(query, params),
                timeout=30.0  # 30 second timeout
            )
        except asyncio.TimeoutError:
            raise QueryTimeout("Query exceeded 30 second timeout")
        
        # 6. Result size check
        if len(result.nodes) > self.MAX_NODES_PER_QUERY:
            raise ResultSizeExceeded(
                f"Query returned {len(result.nodes)} nodes, exceeds limit {self.MAX_NODES_PER_QUERY}"
            )
        
        # 7. Audit logging
        await self.audit.log_audit_event(
            self.graph,
            'query_executed',
            user_id,
            params.get('session_id', 'unknown'),
            {
                'query_type': query_analysis['type'],
                'depth': query_analysis['max_depth'],
                'nodes': [n.id for n in result.nodes[:10]],  # Sample
                'paths': query_analysis['paths']
            }
        )
        
        return result
    
    def _analyze_query(self, query: str, params: dict) -> dict:
        """Analyze query for security-relevant properties."""
        # Simplified analysis - production would use proper parser
        
        depth = 1
        if '*' in query:
            # Variable-length path
            import re
            match = re.search(r'\*(\d+)?\.\.(\d+)', query)
            if match:
                depth = int(match.group(2)) if match.group(2) else 10
        
        return {
            'type': 'read' if query.strip().upper().startswith('MATCH') else 'write',
            'max_depth': depth,
            'paths': []  # Would extract from query
        }
    
    def _check_rate_limit(self, user_id: str) -> bool:
        """Check if user is within rate limits."""
        import time
        
        now = time.time()
        minute_key = f"{user_id}:{int(now / 60)}"
        
        count = self._rate_limiter.get(minute_key, 0)
        if count >= self.RATE_LIMIT_QUERIES_PER_MINUTE:
            return False
        
        self._rate_limiter[minute_key] = count + 1
        return True
    
    def _check_permissions(self, user_id: str, required: List[str]) -> bool:
        """Check user permissions (simplified)."""
        # Production would integrate with IAM/RBAC system
        return True
```

---

## Implementation Phases

### Phase 0-2 Weeks: Core Value Validation

**Goal:** Prove bi-temporal traces improve explainability without breaking existing functionality.

**Deliverables:**
- [ ] Add `decision_trace` block to `/api/v1/graph/session/build` response
- [ ] Implement four-timestamp fields on Evidence and Decision nodes
- [ ] Add `as_of` parameter with basic timestamp filtering
- [ ] Extend identity stitching with `canonical_id`, `aliases`, `stitch_quality`
- [ ] Basic ingestion delta calculation (no anomaly detection yet)

**Success Metric:** Can replay a 7-day-old session via `as_of` and get identical trace.

**Files to modify:**
- `src/api/graph_sessions.py` - Add decision_trace to response
- `src/core/correlation/` - Add trace generation hooks
- `src/api/app.py` - Add as_of parameter handling

**Deferred:**
- Neo4j adapter
- ExplanationCache
- Precedent matching
- RBAC

### Phase 3-6 Weeks: Production Hardening

**Goal:** Make traces useful for T1 analyst workflow.

**Deliverables:**
- [ ] ExplanationCache node type and generation logic
- [ ] Pre-computed natural language explanations
- [ ] Ingestion anomaly detection (EWMA-based)
- [ ] Multi-Domain Health panel integration
- [ ] `as_of` picker in LIVE console
- [ ] Decision Trace panel (right rail)

**Success Metric:** T1 analysts prefer trace-based triage over raw alert view.

**Performance Targets:**
- P95 explanation retrieval: <50ms (cached)
- P95 session build with traces: <500ms
- P95 as_of query: <200ms

**Deferred:**
- GraphStore interface
- Neo4j/Neptune adapters
- Precedent matching
- Property-level RBAC

### Phase 7-12 Weeks: Advanced Features

**Goal:** Enable T2 investigation and compliance readiness.

**Deliverables:**
- [ ] GraphStore interface with Neo4j adapter
- [ ] Precedent matching via embedding similarity
- [ ] Blast radius pathfinding (4-hop limit)
- [ ] T2 GraphRAG-lite summaries
- [ ] Property-level RBAC
- [ ] Audit logging for all trace queries
- [ ] Risk quantification from traces
- [ ] Compliance report export

**Success Metric:** Pass mock compliance audit with trace exports.

---

## Acceptance Criteria

### Functional Requirements

| ID | Requirement | Validation Method |
|----|-------------|-------------------|
| F1 | `as_of` reads return deterministic trace snapshots | Replay test: same as_of = same result |
| F2 | Decision Trace panel renders in LIVE console | UI test |
| F3 | Ingestion lag indicators visible in Multi-Domain Health | UI test |
| F4 | ExplanationCache returns within 50ms P95 | Load test |
| F5 | Bi-temporal gaps trigger ingestion anomaly factors | Unit test |

### Performance Requirements

| ID | Requirement | Target | Validation |
|----|-------------|--------|------------|
| P1 | Session build latency (with trace) | P95 < 500ms | Load test |
| P2 | as_of query latency (cached) | P95 < 200ms | Load test |
| P3 | Explanation retrieval (cached) | P95 < 50ms | Load test |
| P4 | Traversal depth limit enforced | Max 6 hops | Security test |

### Compliance Requirements

| ID | Requirement | Framework | Validation |
|----|-------------|-----------|------------|
| C1 | Decisions logged with timestamps | EU AI Act Art. 12 | Audit export review |
| C2 | Explanations generated for high-severity | EU AI Act Art. 14 | Coverage report |
| C3 | Traversal paths audited | ISO 27001 A.8.15 | Audit log analysis |
| C4 | intended_purpose documented | NIST AI RMF MAP 1.1 | Schema validation |

### Quality Requirements

| ID | Requirement | Target | Validation |
|----|-------------|--------|------------|
| Q1 | Mapping semantics improve correlation confidence | +10% when ≥3 high-value fields | A/B test |
| Q2 | Blind spot risk quantifiable per domain | 0.0-1.0 score | Unit test |
| Q3 | Risk quantification outputs derivable from traces | Expected loss bands | Integration test |

---

## Appendix: Quick Reference

### Cypher Query Patterns

```cypher
-- Get decision trace for session
MATCH (s:Session {session_id: $sid})-[:CONTAINS]->(d:Decision)
OPTIONAL MATCH (d)-[:CONSUMES]->(e:Evidence)
OPTIONAL MATCH (d)-[:EVALUATES]->(p:PolicyEval)
OPTIONAL MATCH (d)-[:PRODUCES]->(o:Outcome)
RETURN s, collect(DISTINCT d) as decisions, 
       collect(DISTINCT e) as evidence,
       collect(DISTINCT p) as policies,
       collect(DISTINCT o) as outcomes

-- Point-in-time reconstruction
MATCH (d:Decision {decision_id: $did})
WHERE datetime(d.t_created) <= $as_of
  AND (d.t_expired IS NULL OR datetime(d.t_expired) > $as_of)
RETURN d

-- Ingestion health check
MATCH (e:Evidence)
WHERE e.t_created >= datetime() - duration('PT1H')
RETURN e.source_system,
       avg(e.ingestion_delta_ms) as avg_latency,
       percentileCont(e.ingestion_delta_ms, 0.95) as p95_latency,
       count(*) as volume

-- Blast radius (4-hop limit)
MATCH (d:Decision {decision_id: $did})-[:CONSUMES]->(e:Evidence)
      -[:OBSERVED_ON]->(start)
MATCH path = (start)-[*1..4]-(affected)
WHERE affected:Identity OR affected:Device OR affected:CloudResource
RETURN count(DISTINCT affected) as blast_radius,
       collect(DISTINCT labels(affected)[0]) as affected_types
```

### Key Configuration Values

```python
# Bi-temporal
EWMA_ALPHA = 0.1
INGESTION_LATENCY_WARNING_MS = 60000
INGESTION_LATENCY_CRITICAL_MS = 300000
VOLUME_DROP_THRESHOLD = 0.5

# Performance
MAX_TRAVERSAL_DEPTH_REALTIME = 4
MAX_TRAVERSAL_DEPTH_ASYNC = 6
QUERY_TIMEOUT_SECONDS = 30
EXPLANATION_CACHE_TTL_SECONDS = 604800  # 7 days

# Compliance
AUDIT_RETENTION_DAYS = 2555  # 7 years for EU AI Act
```

---

*Document Version: 2.0*
*Last Updated: January 2026*
*Author: JanuSec Architecture Team*
