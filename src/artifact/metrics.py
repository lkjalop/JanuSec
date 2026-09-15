from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

artifact_ingest_total = Counter('artifact_ingest_total','Total artifacts ingested', ['type'])
artifact_factor_total = Counter('artifact_factor_total','Factor occurrence', ['factor'])
artifact_verdict_total = Counter('artifact_verdict_total','Artifact verdicts', ['verdict'])
artifact_llm_invocations_total = Counter('artifact_llm_invocations_total','LLM refinement invocations')
artifact_reputation_queries_total = Counter('artifact_reputation_queries_total','Reputation queries attempted')
artifact_reputation_cache_hits_total = Counter('artifact_reputation_cache_hits_total','Reputation cache hits')
artifact_risk_score = Histogram('artifact_risk_score','Artifact final risk score distribution',buckets=[0,0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9,1.0])
artifact_processing_latency = Histogram('artifact_processing_latency_seconds','Per batch processing time')
artifact_cost_estimate = Gauge('artifact_cost_estimate_usd','Estimated cost of last batch USD')
artifact_rare_prevalence_total = Counter('artifact_rare_prevalence_total','Artifacts flagged rare_prevalence')
artifact_ambiguity_band_total = Counter('artifact_ambiguity_band_total','Artifacts falling into ambiguity band for refinement')
