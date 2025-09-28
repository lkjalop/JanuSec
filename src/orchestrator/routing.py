from __future__ import annotations

import asyncio
import time
from typing import Any, Dict

from repositories import alerts_repo, audit_repo, events_repo

from .types import ProcessingResult


class RoutingMixin:
    module_registry: Any
    event_pipeline: Any
    decision_engine: Any
    metrics: Any
    config: Any
    adaptive_tuner: Any
    xdr_connector: Any
    logger: Any
    factor_weights: dict[str, float]

    async def process_event(self, event: Dict[str, Any]) -> ProcessingResult:
        start_time = time.time()
        event_id = event.get('id', 'unknown')

        try:
            self.events_processed += 1
            await self.metrics.record_event_ingestion(event)
            await self._persist_raw_event(event)

            async with asyncio.timeout(1.0):
                pipeline_result = await self.event_pipeline.process_event(event)

            routing_decision = await self.decision_engine.make_decision(pipeline_result)
            routing_decision.stage_timings = routing_decision.stage_timings or getattr(pipeline_result, 'stage_timings', [])
            routing_decision.processing_time = routing_decision.processing_time or getattr(pipeline_result, 'processing_time', 0.0)
            routing_decision.config_digests = routing_decision.config_digests or self.config.get_current_digests()
            routing_decision.custody_hash = routing_decision.custody_hash or self._calculate_custody_hash(event, routing_decision.factors)

            self._apply_factor_weights(routing_decision)

            final_result = await self._execute_routing_decision(event, routing_decision)
            await self.xdr_connector.update_verdict(final_result.event_id, final_result.verdict, final_result.confidence)
            await self.adaptive_tuner.record_decision(final_result)

            processing_time = (time.time() - start_time) * 1000
            await self.metrics.record_processing_complete(final_result, processing_time)
            await self._persist_decision(event, final_result)
            return final_result

        except asyncio.TimeoutError:
            self.logger.warning("Event %s processing timeout - using fallback", event_id)
            await self._record_fallback_usage()
            fallback = await self._fallback_processing(event)
            await self._attempt_persist_decision(event, fallback)
            return fallback
        except Exception as exc:
            self.logger.error("Error processing event %s: %s", event_id, exc)
            await self.metrics.record_processing_error(event_id, str(exc))
            await self._record_fallback_usage()
            fallback = await self._error_fallback(event, str(exc))
            await self._attempt_persist_decision(event, fallback)
            return fallback

    async def _persist_raw_event(self, event: Dict[str, Any]) -> None:
        try:
            await events_repo.upsert_event(event)
        except Exception as exc:
            try:
                self.logger.debug("Event persistence skipped: %s", exc)
            except Exception:
                pass

    def _apply_factor_weights(self, decision) -> None:
        if not self.factor_weights:
            return
        try:
            adjustment = 0.0
            for factor in decision.factors:
                weight = self.factor_weights.get(factor)
                if weight:
                    adjustment += weight
            if adjustment:
                base = decision.confidence
                decision.confidence = max(0.0, min(1.0, base * (1.0 + adjustment)))
        except Exception:
            pass

    async def _execute_routing_decision(self, event: Dict[str, Any], decision) -> ProcessingResult:
        if decision.path == 'benign':
            return await self._fast_benign_path(event, decision)
        if decision.path == 'malicious':
            return await self._fast_malicious_path(event, decision)
        return await self._deep_analysis_path(event, decision)

    async def _fast_benign_path(self, event: Dict[str, Any], decision) -> ProcessingResult:
        baseline_module = await self.module_registry.get_module('baseline')
        await baseline_module.learn_benign(event)
        storage_manager = await self.module_registry.get_module('storage_manager')
        await storage_manager.schedule_archive(event)
        return ProcessingResult(
            event_id=event['id'],
            verdict='benign',
            confidence=decision.confidence,
            processing_time_ms=decision.processing_time,
            factors=list(decision.factors),
            stage_timings=decision.stage_timings or [],
            config_digests=decision.config_digests or self.config.get_current_digests(),
            custody_hash=decision.custody_hash or self._calculate_custody_hash(event, decision.factors),
        )

    async def _fast_malicious_path(self, event: Dict[str, Any], decision) -> ProcessingResult:
        playbook_executor = await self.module_registry.get_module('playbook_executor')
        execution_result = await playbook_executor.execute_for_decision(decision)
        await self._generate_alert(event, decision, execution_result)
        return ProcessingResult(
            event_id=event['id'],
            verdict='malicious',
            confidence=decision.confidence,
            processing_time_ms=decision.processing_time,
            factors=list(decision.factors) + ['playbook_executed'],
            stage_timings=decision.stage_timings or [],
            config_digests=decision.config_digests or self.config.get_current_digests(),
            custody_hash=decision.custody_hash or self._calculate_custody_hash(event, decision.factors),
        )

    async def _deep_analysis_path(self, event: Dict[str, Any], decision) -> ProcessingResult:
        analysis_result = await self.event_pipeline.deep_analysis(event, decision)
        final_decision = await self.decision_engine.finalize_decision(analysis_result)
        final_verdict = getattr(final_decision, 'verdict', 'suspicious')
        final_processing_time = getattr(final_decision, 'processing_time', 0.0)
        final_stage_timings = getattr(final_decision, 'stage_timings', [])
        final_config = getattr(final_decision, 'config_digests', None) or self.config.get_current_digests()
        final_custody = getattr(final_decision, 'custody_hash', None) or self._calculate_custody_hash(event, final_decision.factors)
        if final_verdict == 'malicious' and final_decision.confidence > 0.8:
            playbook_executor = await self.module_registry.get_module('playbook_executor')
            await playbook_executor.execute_for_decision(final_decision)
        return ProcessingResult(
            event_id=event['id'],
            verdict=final_verdict,
            confidence=final_decision.confidence,
            processing_time_ms=final_processing_time,
            factors=list(final_decision.factors),
            stage_timings=final_stage_timings,
            config_digests=final_config,
            custody_hash=final_custody,
        )

    async def _fallback_processing(self, event: Dict[str, Any]) -> ProcessingResult:
        baseline_module = await self.module_registry.get_module('baseline')
        result = await baseline_module.quick_check(event)
        return ProcessingResult(
            event_id=event['id'],
            verdict='suspicious' if result.confidence > 0.5 else 'benign',
            confidence=result.confidence,
            processing_time_ms=1000.0,
            factors=list(result.factors) + ['processing_timeout'],
            stage_timings=[{'baseline': result.processing_time}],
            config_digests=self.config.get_current_digests(),
            custody_hash=self._calculate_custody_hash(event, result.factors),
        )

    async def _error_fallback(self, event: Dict[str, Any], error: str) -> ProcessingResult:
        return ProcessingResult(
            event_id=event['id'],
            verdict='suspicious',
            confidence=0.5,
            processing_time_ms=0.0,
            factors=['processing_error'],
            stage_timings=[],
            config_digests=self.config.get_current_digests(),
            custody_hash=self._calculate_custody_hash(event, ['processing_error']),
        )

    async def _generate_alert(self, event: Dict[str, Any], decision, execution_result) -> None:
        tenant_id = event.get('tenant_id')
        alert_data = {
            'event_id': event['id'],
            'verdict': decision.verdict,
            'confidence': decision.confidence,
            'factors': decision.factors,
            'playbook_result': execution_result,
            'timestamp': time.time(),
            'tenant_id': tenant_id,
        }
        await self.metrics.record_alert_generated(alert_data)
        if self.slack_notifier:
            ok = await self.slack_notifier.send_alert(
                severity=event.get('severity', 'low'),
                text=f"[{decision.verdict.upper()}] event {event['id']} confidence={decision.confidence:.2f}",
            )
            if not ok:
                await self.metrics.record_slack_failure()
        try:
            await alerts_repo.insert_alert(
                event_id=event['id'],
                verdict=decision.verdict,
                confidence=decision.confidence,
                severity=event.get('severity', 'unknown'),
                factors=decision.factors,
                playbook_result=execution_result,
                tenant_id=tenant_id,
            )
        except Exception as exc:
            try:
                self.logger.debug('Alert persistence skipped: %s', exc)
            except Exception:
                pass
        await self._append_alert_audit(event, decision, alert_data)
        await self._persist_evidence(event, alert_data)

    async def _append_alert_audit(self, event: Dict[str, Any], decision, alert_data: Dict[str, Any]) -> None:
        try:
            tenant_id = event.get('tenant_id')
            try:
                prev_hash = await audit_repo.get_last_hash(event['id'], tenant_id)
            except Exception:
                prev_hash = None
            computed_decision_hash = self._calculate_custody_hash(event, decision.factors)
            custody_hash = self._calculate_custody_hash(event, decision.factors + ['alert_generated'])
            prev_hash = prev_hash or computed_decision_hash
            await audit_repo.append_audit(event['id'], 'alert_generated', alert_data, custody_hash, prev_hash, tenant_id)
        except Exception as exc:
            try:
                self.logger.debug('Alert audit skipped: %s', exc)
            except Exception:
                pass
    async def _persist_evidence(self, event: Dict[str, Any], alert_data: Dict[str, Any]) -> None:
        try:
            evidence = alert_data.get('evidence')
            if evidence:
                from live import evidence_store as evidence_store  # type: ignore
                evidence_store.append(
                    {
                        'event_id': event['id'],
                        'ts': alert_data.get('timestamp'),
                        'evidence': evidence,
                    }
                )
        except Exception:
            pass

    async def _record_fallback_usage(self) -> None:
        try:
            await self.metrics.record_fallback_tier_usage()
        except Exception:
            pass

    async def _attempt_persist_decision(self, event: Dict[str, Any], result: ProcessingResult) -> None:
        try:
            await self._persist_decision(event, result)
        except Exception as exc:
            try:
                self.logger.debug('Decision persistence skipped: %s', exc)
            except Exception:
                pass
