"""
Pragmatic Security Threat Sifting Platform - Main Orchestrator
Author: Security Engineering Team
Version: 1.0.0

Main orchestration engine with circuit breakers, health checks, and adaptive tuning.
Keeps to 350 lines by delegating complex logic to specialized modules.
"""

import asyncio
import logging
import time
from typing import Dict, Any, Optional
from dataclasses import dataclass
from contextlib import asynccontextmanager

from core.module_registry import ModuleRegistry
from core.event_pipeline import EventPipeline
from core.decision_engine import DecisionEngine
from core.metrics_collector import MetricsCollector
from core.config_manager import ConfigManager
from adapters.eclipse_xdr import EclipseXDRConnector
from modules.adaptive_tuner import AdaptiveTuner
from db import database as db
from repositories import events_repo, decisions_repo, alerts_repo, audit_repo
from repositories import factors_repo
from repositories import factor_weights_repo
from repositories import feedback_repo
from integrations.slack_notifier import SlackNotifier
from maintenance.vector_index_maintainer import maintenance_loop as vector_index_maintenance_loop
from analytics.drift_analyzer import drift_loop


@dataclass
class ProcessingResult:
    """Result of event processing with full audit trail"""
    event_id: str
    verdict: str
    confidence: float
    processing_time_ms: float
    factors: list[str]
    stage_timings: Dict[str, float]
    config_digests: Dict[str, str]
    custody_hash: str


class SecurityOrchestrator:
    """
    Main orchestrator with circuit breakers and health checks.
    Coordinates all modules while maintaining strict performance bounds.
    """

    def __init__(self, config_path: str = "config/main.yaml"):
        self.config = ConfigManager(config_path)
        self.module_registry = ModuleRegistry(self.config)
        self.event_pipeline = EventPipeline(self.config)
        self.decision_engine = DecisionEngine(self.config)
        self.metrics = MetricsCollector(self.config)
        self.adaptive_tuner = AdaptiveTuner(self.config)
    self.factor_weights: dict[str,float] = {}
        
        # External integrations
        self.xdr_connector = EclipseXDRConnector(self.config)
        # Slack notifier (lazy init once config loaded)
        self.slack_notifier: SlackNotifier | None = None
        
        # Performance tracking
        self.events_processed = 0
        self.start_time = time.time()
        self.health_status = "starting"
        
        # Circuit breaker states
        self.circuit_breakers = {}
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        # Provide back-reference for pipeline module access
        try:
            self.event_pipeline.config.module_registry = self.module_registry
        except Exception:
            pass
        
    async def initialize(self):
        """Initialize all modules with health checks"""
        self.logger.info("Initializing Security Orchestrator...")
        
        try:
            # Initialize database pool (best-effort; continue if unavailable)
            try:
                await db.init_pool()
            except Exception as db_err:  # pragma: no cover - continues without DB
                self.logger.warning(f"Database initialization failed or skipped: {db_err}")
            # Initialize core modules
            await self.module_registry.initialize()
            await self.event_pipeline.initialize()
            await self.decision_engine.initialize()
            await self.metrics.initialize()
            await self.adaptive_tuner.initialize()
            
            # Initialize external connectors
            await self.xdr_connector.initialize()
            # Configure Slack notifier if enabled
            try:
                slack_cfg = self.config.get('slack') if hasattr(self.config, 'get') else None
                if slack_cfg and getattr(slack_cfg, 'enabled', False):
                    channel_map = {}
                    if getattr(slack_cfg, 'channel_map', None):
                        channel_map = {k: v for k, v in slack_cfg.channel_map.model_dump().items() if v}
                    self.slack_notifier = SlackNotifier(
                        webhook_url=slack_cfg.webhook_url,
                        default_channel=slack_cfg.default_channel,
                        channel_map=channel_map,
                        rate_limit_per_minute=slack_cfg.rate_limit_per_minute,
                    )
                    self.logger.info("Slack notifier enabled")
            except Exception as e:  # pragma: no cover
                self.logger.warning(f"Slack notifier init failed: {e}")
            
            # Start background tasks
            asyncio.create_task(self.health_monitor())
            asyncio.create_task(self.adaptive_tuning_loop())
            asyncio.create_task(self.metrics_collection_loop())
            # Vector index maintenance (best-effort, no-fail)
            try:
                if not hasattr(self, '_maintenance_stop'):
                    self._maintenance_stop = asyncio.Event()
                asyncio.create_task(vector_index_maintenance_loop(self._maintenance_stop))
            except Exception:
                pass
            # Feedback weight aggregation loop
            try:
                asyncio.create_task(self.feedback_weight_loop())
            except Exception:
                pass
            # Drift loop
            try:
                if not hasattr(self, '_drift_stop'):
                    self._drift_stop = asyncio.Event()
                asyncio.create_task(drift_loop(self.metrics, self._drift_stop))
            except Exception:
                pass
            
            self.health_status = "healthy"
            self.logger.info("Security Orchestrator initialized successfully")
            
        except Exception as e:
            self.health_status = "failed"
            self.logger.error(f"Failed to initialize: {e}")
            raise

    async def process_event(self, event: Dict[str, Any]) -> ProcessingResult:
        """
        Main event processing with progressive enhancement and adaptive tuning.
        Maintains strict performance bounds while providing rich analysis.
        """
        start_time = time.time()
        event_id = event.get('id', 'unknown')
        
        try:
            self.events_processed += 1
            
            # Record event ingestion
            await self.metrics.record_event_ingestion(event)

            # Persist raw event (ignore errors to not impact pipeline)
            try:
                await events_repo.upsert_event(event)
            except Exception as e:  # pragma: no cover
                self.logger.debug(f"Event persistence skipped: {e}")
            
            # Process through pipeline with timeout protection
            with asyncio.timeout(1.0):  # 1 second max processing time
                result = await self.event_pipeline.process_event(event)
            
            # Make routing decision
            routing_decision = await self.decision_engine.make_decision(result)

            # Apply feedback weighting before routing execution (adjust provisional confidence)
            try:
                if self.factor_weights:
                    adj = 0.0
                    for f in routing_decision.factors:
                        w = self.factor_weights.get(f)
                        if w:
                            adj += w
                    if adj != 0:
                        base = routing_decision.confidence
                        routing_decision.confidence = max(0.0, min(1.0, base * (1.0 + adj)))
            except Exception:
                pass
            
            # Execute based on routing
            final_result = await self._execute_routing_decision(event, routing_decision)
            
            # Update XDR with verdict
            await self.xdr_connector.update_verdict(
                event_id, 
                final_result.verdict, 
                final_result.confidence
            )
            
            # Feed back to adaptive tuner
            await self.adaptive_tuner.record_decision(final_result)
            
            # Record metrics
            processing_time = (time.time() - start_time) * 1000
            await self.metrics.record_processing_complete(final_result, processing_time)

            # Persist decision & audit log
            await self._persist_decision(event, final_result)
            
            return final_result
            
        except asyncio.TimeoutError:
            self.logger.warning(f"Event {event_id} processing timeout - using fallback")
            try:
                await self.metrics.record_fallback_tier_usage()
            except Exception:
                pass
            return await self._fallback_processing(event)
            
        except Exception as e:
            self.logger.error(f"Error processing event {event_id}: {e}")
            await self.metrics.record_processing_error(event_id, str(e))
            try:
                await self.metrics.record_fallback_tier_usage()
            except Exception:
                pass
            return await self._error_fallback(event, str(e))

    async def _execute_routing_decision(self, event: Dict[str, Any], decision) -> ProcessingResult:
        """Execute the routing decision with appropriate action"""
        
        if decision.path == 'benign':
            return await self._fast_benign_path(event, decision)
        elif decision.path == 'malicious':
            return await self._fast_malicious_path(event, decision)
        else:
            return await self._deep_analysis_path(event, decision)

    async def _fast_benign_path(self, event: Dict[str, Any], decision) -> ProcessingResult:
        """Handle obviously benign events quickly"""
        # Update baseline learning
        await self.module_registry.get_module('baseline').learn_benign(event)
        
        # Schedule for archival
        await self.module_registry.get_module('storage').schedule_archive(event)
        
        return ProcessingResult(
            event_id=event['id'],
            verdict='benign',
            confidence=decision.confidence,
            processing_time_ms=decision.processing_time,
            factors=decision.factors,
            stage_timings=decision.stage_timings,
            config_digests=decision.config_digests,
            custody_hash=decision.custody_hash
        )

    async def _fast_malicious_path(self, event: Dict[str, Any], decision) -> ProcessingResult:
        """Handle obvious threats with immediate response"""
        # Execute appropriate playbook
        playbook_executor = self.module_registry.get_module('playbook_executor')
        execution_result = await playbook_executor.execute_for_decision(decision)
        
        # Generate alert
        await self._generate_alert(event, decision, execution_result)
        
        return ProcessingResult(
            event_id=event['id'],
            verdict='malicious',
            confidence=decision.confidence,
            processing_time_ms=decision.processing_time,
            factors=decision.factors + ['playbook_executed'],
            stage_timings=decision.stage_timings,
            config_digests=decision.config_digests,
            custody_hash=decision.custody_hash
        )

    async def _deep_analysis_path(self, event: Dict[str, Any], decision) -> ProcessingResult:
        """Handle uncertain events with comprehensive analysis"""
        # Enhanced analysis through multiple modules
        analysis_result = await self.event_pipeline.deep_analysis(event, decision)
        
        # Final decision after deep analysis
        final_decision = await self.decision_engine.finalize_decision(analysis_result)
        
        if final_decision.verdict == 'malicious' and final_decision.confidence > 0.8:
            # Execute playbook after deep analysis confirms threat
            playbook_executor = self.module_registry.get_module('playbook_executor')
            await playbook_executor.execute_for_decision(final_decision)
        
        return ProcessingResult(
            event_id=event['id'],
            verdict=final_decision.verdict,
            confidence=final_decision.confidence,
            processing_time_ms=final_decision.processing_time,
            factors=final_decision.factors,
            stage_timings=final_decision.stage_timings,
            config_digests=final_decision.config_digests,
            custody_hash=final_decision.custody_hash
        )

    async def _fallback_processing(self, event: Dict[str, Any]) -> ProcessingResult:
        """Fallback processing when main pipeline times out"""
        baseline_module = self.module_registry.get_module('baseline')
        result = await baseline_module.quick_check(event)
        
        return ProcessingResult(
            event_id=event['id'],
            verdict='suspicious' if result.confidence > 0.5 else 'benign',
            confidence=result.confidence,
            processing_time_ms=1000.0,  # Timeout occurred
            factors=result.factors + ['processing_timeout'],
            stage_timings={'baseline': result.processing_time},
            config_digests=self.config.get_current_digests(),
            custody_hash=self._calculate_custody_hash(event, result.factors)
        )

    async def _error_fallback(self, event: Dict[str, Any], error: str) -> ProcessingResult:
        """Fallback when processing fails completely"""
        return ProcessingResult(
            event_id=event['id'],
            verdict='suspicious',
            confidence=0.5,
            processing_time_ms=0.0,
            factors=['processing_error'],
            stage_timings={},
            config_digests=self.config.get_current_digests(),
            custody_hash=self._calculate_custody_hash(event, ['processing_error'])
        )

    async def _generate_alert(self, event: Dict[str, Any], decision, execution_result):
        """Generate and send alerts for malicious events"""
        alert_data = {
            'event_id': event['id'],
            'verdict': decision.verdict,
            'confidence': decision.confidence,
            'factors': decision.factors,
            'playbook_result': execution_result,
            'timestamp': time.time()
        }
        
        # Send to various notification channels
        await self.metrics.record_alert_generated(alert_data)
        # Slack notification
        if self.slack_notifier:
            ok = await self.slack_notifier.send_alert(
                severity=event.get('severity', 'low'),
                text=f"[{decision.verdict.upper()}] event {event['id']} confidence={decision.confidence:.2f}",
            )
            if not ok:
                await self.metrics.record_slack_failure()
        # Persist alert
        try:
            severity = event.get('severity', 'unknown')
            await alerts_repo.insert_alert(
                event_id=event['id'],
                verdict=decision.verdict,
                confidence=decision.confidence,
                severity=severity,
                factors=decision.factors,
                playbook_result=execution_result
            )
            # Audit entry for alert
            prev_hash = await audit_repo.get_last_hash(event['id'])
            custody_hash = self._calculate_custody_hash(event, decision.factors + ['alert_generated'])
            await audit_repo.append_audit(event['id'], 'alert_generated', alert_data, custody_hash, prev_hash)
        except Exception as e:  # pragma: no cover
            self.logger.debug(f"Alert persistence skipped: {e}")

    def _calculate_custody_hash(self, event: Dict[str, Any], factors: list[str]) -> str:
        """Calculate cryptographic hash for chain of custody"""
        import hashlib
        import json
        
        custody_data = {
            'event_id': event['id'],
            'timestamp': event.get('timestamp'),
            'factors': sorted(factors),
            'config_digests': self.config.get_current_digests()
        }
        
        canonical_json = json.dumps(custody_data, sort_keys=True)
        return hashlib.sha256(canonical_json.encode()).hexdigest()

    async def _persist_decision(self, event: Dict[str, Any], result: ProcessingResult):
        """Persist decision and append audit log with custody chaining"""
        try:
            # Decision persistence
            await decisions_repo.upsert_decision(event['id'], result)
            # Try factor embeddings (lightweight): hash-based embedding or transformer if available
            try:
                factors = [f for f in result.factors if isinstance(f, str) and ':' not in f][:25]
                embedder = None
                vec_cache = {}
                try:
                    from transformers import AutoTokenizer, AutoModel  # type: ignore
                    if not hasattr(self, '_embedding_model'):
                        self._embedding_tokenizer = AutoTokenizer.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
                        self._embedding_model = AutoModel.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
                    embedder = (self._embedding_tokenizer, self._embedding_model)
                except Exception:
                    embedder = None
                for fx in factors:
                    emb: list[float]
                    if embedder:
                        import torch
                        with torch.no_grad():
                            toks = self._embedding_tokenizer(fx, return_tensors='pt', truncation=True)
                            out = self._embedding_model(**toks)
                            v = out.last_hidden_state.mean(dim=1).squeeze().tolist()
                            if isinstance(v, float):
                                v = [v]
                            emb = v[:384]
                    else:
                        # Hash fallback deterministic pseudo-embedding
                        import hashlib
                        h = hashlib.sha256(fx.encode()).digest()
                        emb = [b/255.0 for b in h][:32]
                    await factors_repo.insert_embedding(event['id'], fx, emb)
            except Exception as e:  # pragma: no cover
                self.logger.debug(f"Embedding persistence skipped: {e}")
            # Audit chaining
            prev_hash = await audit_repo.get_last_hash(event['id'])
            await audit_repo.append_audit(
                event_id=event['id'],
                action='decision_recorded',
                details={
                    'verdict': result.verdict,
                    'confidence': result.confidence,
                    'factors': result.factors
                },
                custody_hash=result.custody_hash,
                prev_hash=prev_hash
            )
        except Exception as e:  # pragma: no cover
            self.logger.debug(f"Decision persistence skipped: {e}")

    async def health_monitor(self):
        """Background health monitoring and circuit breaker management"""
        while True:
            try:
                # Check module health
                health_status = await self.module_registry.health_check()
                
                if not health_status['healthy']:
                    self.logger.warning(f"Unhealthy modules detected: {health_status['unhealthy']}")
                    self.health_status = "degraded"
                else:
                    self.health_status = "healthy"
                
                # Update metrics
                await self.metrics.record_health_status(self.health_status)
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Health monitor error: {e}")
                await asyncio.sleep(60)

    async def adaptive_tuning_loop(self):
        """Background adaptive tuning process"""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                # Run adaptive tuning
                tuning_results = await self.adaptive_tuner.run_tuning_cycle()
                
                if tuning_results.has_recommendations:
                    self.logger.info(f"Adaptive tuning recommendations: {tuning_results.summary}")
                    
                    # Apply approved changes
                    await self._apply_tuning_recommendations(tuning_results)
                
            except Exception as e:
                self.logger.error(f"Adaptive tuning error: {e}")

    async def metrics_collection_loop(self):
        """Background metrics collection and reporting"""
        while True:
            try:
                await asyncio.sleep(60)  # Collect every minute
                
                # Collect system metrics
                system_metrics = {
                    'events_processed_total': self.events_processed,
                    'uptime_seconds': time.time() - self.start_time,
                    'health_status': self.health_status
                }
                
                await self.metrics.record_system_metrics(system_metrics)
                # Compute average embedding norm (best-effort)
                try:
                    from db.database import get_pool
                    pool = await get_pool()
                    async with pool.acquire() as conn:
                        rows = await conn.fetch("SELECT embedding_json FROM factor_embeddings ORDER BY id DESC LIMIT 200")
                        norms = []
                        for r in rows:
                            emb = r.get('embedding_json')
                            if isinstance(emb, list) and emb:
                                s = sum(x*x for x in emb) ** 0.5
                                norms.append(s)
                        if norms:
                            avg_norm = sum(norms)/len(norms)
                            await self.metrics.record_embedding_stats(avg_norm)
                except Exception:
                    pass
                
            except Exception as e:
                self.logger.error(f"Metrics collection error: {e}")

    async def feedback_weight_loop(self):
        """Periodically aggregate factor feedback into weights.

        Simple heuristic: weight = (up - down) / (up + down + smoothing) * scale
        scale defaults to 0.1 so max +/-10% adjustment per strongly signaled factor.
        """
        smoothing = 5
        scale = 0.1
        while True:
            try:
                from db.database import get_pool
                pool = await get_pool()
                async with pool.acquire() as conn:
                    rows = await conn.fetch("""
                        SELECT factor,
                               sum(CASE WHEN vote=1 THEN 1 ELSE 0 END) AS up,
                               sum(CASE WHEN vote=-1 THEN 1 ELSE 0 END) AS down
                        FROM factor_feedback
                        GROUP BY factor
                        LIMIT 1000
                    """)
                    new_weights: dict[str,float] = {}
                    for r in rows:
                        up = r['up'] or 0
                        down = r['down'] or 0
                        total = up + down
                        if total == 0:
                            continue
                        w = ((up - down) / (total + smoothing)) * scale
                        # Clamp +/-0.25 safety
                        w = max(-0.25, min(0.25, w))
                        new_weights[r['factor']] = w
                        try:
                            await factor_weights_repo.upsert_factor_weight(r['factor'], w)
                        except Exception:
                            pass
                    self.factor_weights = new_weights
            except Exception as e:
                self.logger.debug(f"Feedback weight aggregation skipped: {e}")
            await asyncio.sleep(300)  # every 5 minutes

    async def _apply_tuning_recommendations(self, recommendations):
        """Apply adaptive tuning recommendations with approval gates"""
        for rec in recommendations.changes:
            if rec.confidence > 0.8 and rec.risk_level == 'low':
                # Auto-apply low-risk changes
                await self._apply_recommendation(rec)
            else:
                # Queue for manual approval
                await self.adaptive_tuner.queue_for_approval(rec)

    async def _apply_recommendation(self, recommendation):
        """Apply a specific tuning recommendation"""
        if recommendation.type == 'threshold_adjustment':
            await self.decision_engine.update_thresholds(recommendation.parameters)
        elif recommendation.type == 'pattern_optimization':
            regex_module = self.module_registry.get_module('regex_engine')
            await regex_module.update_patterns(recommendation.parameters)

    async def shutdown(self):
        """Graceful shutdown of all components"""
        self.logger.info("Starting graceful shutdown...")
        
        # Stop processing new events
        self.health_status = "shutting_down"
        
        # Shutdown modules
        await self.module_registry.shutdown()
        await self.event_pipeline.shutdown()
        await self.decision_engine.shutdown()
        await self.adaptive_tuner.shutdown()
        await self.xdr_connector.shutdown()
        
        # Final metrics flush
        await self.metrics.flush_and_shutdown()
        
        self.logger.info("Shutdown complete")


async def main():
    """Main entry point"""
    orchestrator = SecurityOrchestrator()
    
    try:
        await orchestrator.initialize()
        
        # Start event processing (this would typically be triggered by XDR events)
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        await orchestrator.shutdown()


if __name__ == "__main__":
    asyncio.run(main())