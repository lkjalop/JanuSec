from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, List

from repositories import audit_repo, decisions_repo, factors_repo

from .types import ProcessingResult


class DecisionPersistenceMixin:
    config: Any
    logger: Any

    def _calculate_custody_hash(self, event: dict[str, Any], factors: list[str]) -> str:
        """Calculate cryptographic hash for chain of custody."""
        custody_data = {
            'event_id': event['id'],
            'timestamp': event.get('timestamp'),
            'factors': sorted(factors),
            'config_digests': self.config.get_current_digests(),
        }
        canonical_json = json.dumps(custody_data, sort_keys=True)
        return hashlib.sha256(canonical_json.encode()).hexdigest()

    async def _persist_decision(self, event: dict[str, Any], result: ProcessingResult) -> None:
        """Persist decision record and append audit chain."""
        fast_mode = os.getenv('FAST_TEST_MODE', '0').lower() in {'1', 'true', 'yes'}
        if fast_mode:
            await self._persist_fast_mode(event, result)
            return

        persistence_error: Exception | None = None
        try:
            await decisions_repo.upsert_decision(event['id'], result, event.get('tenant_id'))
            await self._persist_factor_embeddings(event['id'], result.factors)
            # Trigger shadow A/B assignment for enabled tests (non-blocking)
            try:
                # schedule background assignment to avoid slowing persistence
                try:
                    from src.core.ab.shadow_runner import assign_if_enabled as _assign_if_enabled  # type: ignore
                    from src.repositories import ab_test_repo as _ab_repo  # type: ignore
                    # retrieve active tests and schedule assign_if_enabled for each
                    async def _assign_loop():
                        try:
                            active = await _ab_repo.list_active()
                            for t in (active or []):
                                tid = t.get('id')
                                if not tid:
                                    continue
                                try:
                                    await _assign_if_enabled(tid, event['id'], event.get('tenant_id'))
                                except Exception:
                                    # swallow per-test errors
                                    continue
                        except Exception:
                            pass
                    # schedule as safe background task if possible
                    try:
                        # If tests request synchronous assignment (to avoid
                        # races when asserting background behavior), run the
                        # assign loop inline when ASSIGN_SYNC_FOR_TESTS is set.
                        sync_assign = os.getenv('ASSIGN_SYNC_FOR_TESTS', '0').lower() in {'1','true','yes'}
                        if sync_assign:
                            try:
                                # run inline to make unit tests deterministic
                                await _assign_loop()
                            except Exception:
                                pass
                        else:
                            from src.api.server import safe_task
                            safe_task(_assign_loop(), name='shadow_assign')
                    except Exception:
                        try:
                            # fallback: create task directly
                            import asyncio
                            asyncio.create_task(_assign_loop())
                        except Exception:
                            pass
                except Exception:
                    pass
            except Exception:
                pass
        except Exception as exc:
            persistence_error = exc

        await self._append_audit_chain(event, result, persistence_error)

    async def _persist_fast_mode(self, event: dict[str, Any], result: ProcessingResult) -> None:
        tenant_id = event.get('tenant_id')
        try:
            prev_hash = await audit_repo.get_last_hash(event['id'], tenant_id)
        except Exception:
            prev_hash = None
        custody_hash = getattr(result, 'custody_hash', None) or self._calculate_custody_hash(event, result.factors)
        try:
            await audit_repo.append_audit(
                event_id=event['id'],
                action='decision_recorded',
                details={
                    'verdict': result.verdict,
                    'confidence': result.confidence,
                    'factors': result.factors,
                    'fast_test_mode': True,
                },
                custody_hash=custody_hash,
                prev_hash=prev_hash,
                tenant_id=tenant_id,
            )
        except Exception:
            pass
        if result.verdict == 'malicious':
            try:
                alert_hash = self._calculate_custody_hash(event, result.factors + ['alert_generated'])
                await audit_repo.append_audit(
                    event_id=event['id'],
                    action='alert_generated',
                    details={
                        'verdict': result.verdict,
                        'confidence': result.confidence,
                        'fast_test_mode': True,
                    },
                    custody_hash=alert_hash,
                    prev_hash=custody_hash,
                    tenant_id=tenant_id,
                )
            except Exception:
                pass

        # When running in fast/test mode, allow tests to request a synchronous
        # A/B assignment run so unit tests can deterministically observe it.
        try:
            sync_assign = os.getenv('ASSIGN_SYNC_FOR_TESTS', '0').lower() in {'1','true','yes'}
        except Exception:
            sync_assign = False
        if sync_assign:
            try:
                from src.repositories import ab_test_repo as _ab_repo  # type: ignore
                from src.core.ab.shadow_runner import assign_if_enabled as _assign_if_enabled  # type: ignore
                try:
                    active = await _ab_repo.list_active()
                    for t in (active or []):
                        tid = t.get('id')
                        if not tid:
                            continue
                        try:
                            await _assign_if_enabled(tid, event['id'], tenant_id)
                        except Exception:
                            continue
                except Exception:
                    pass
            except Exception:
                pass

    async def _persist_factor_embeddings(self, event_id: str, factors: list[str]) -> None:
        slim_factors = [f for f in factors if isinstance(f, str) and ':' not in f][:25]
        if not slim_factors:
            return
        embedder = await self._ensure_embedding_model()
        for factor in slim_factors:
            embedding = await self._embed_factor(embedder, factor)
            if embedding is None:
                continue
            try:
                await factors_repo.insert_embedding(event_id, factor, embedding)
            except Exception:
                continue

    async def _ensure_embedding_model(self):  # type: ignore[override]
        if hasattr(self, '_embedding_model') and hasattr(self, '_embedding_tokenizer'):
            return self._embedding_tokenizer, self._embedding_model
        try:
            from transformers import AutoModel, AutoTokenizer  # type: ignore
            self._embedding_tokenizer = AutoTokenizer.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
            self._embedding_model = AutoModel.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
            return self._embedding_tokenizer, self._embedding_model
        except Exception:
            return None

    async def _embed_factor(self, embedder, factor: str) -> list[float] | None:
        if not embedder:
            import hashlib
            digest = hashlib.sha256(factor.encode()).digest()
            return [b / 255.0 for b in digest][:32]
        tokenizer, model = embedder
        try:
            import torch
            with torch.no_grad():
                tokens = tokenizer(factor, return_tensors='pt', truncation=True)
                output = model(**tokens)
                vec = output.last_hidden_state.mean(dim=1).squeeze().tolist()
                if isinstance(vec, float):
                    vec = [vec]
                return vec[:384]
        except Exception as exc:
            try:
                self.logger.debug('Embedding generation failed for %s: %s', factor, exc)
            except Exception:
                pass
            return None

    async def _append_audit_chain(
        self,
        event: dict[str, Any],
        result: ProcessingResult,
        persistence_error: Exception | None,
    ) -> None:
        try:
            tenant_id = event.get('tenant_id')
            try:
                prev_hash = await audit_repo.get_last_hash(event['id'], tenant_id)
            except Exception:
                prev_hash = None
            custody_hash = getattr(result, 'custody_hash', None) or self._calculate_custody_hash(event, result.factors)
            await audit_repo.append_audit(
                event_id=event['id'],
                action='decision_recorded',
                details={
                    'verdict': result.verdict,
                    'confidence': result.confidence,
                    'factors': result.factors,
                    'persistence_error': str(persistence_error) if persistence_error else None,
                },
                custody_hash=custody_hash,
                prev_hash=prev_hash,
                tenant_id=tenant_id,
            )
            if result.verdict == 'malicious':
                try:
                    alert_hash = self._calculate_custody_hash(event, result.factors + ['alert_generated'])
                    await audit_repo.append_audit(
                        event_id=event['id'],
                        action='alert_generated',
                        details={'verdict': result.verdict, 'confidence': result.confidence},
                        custody_hash=alert_hash,
                        prev_hash=custody_hash,
                        tenant_id=tenant_id,
                    )
                except Exception:
                    pass
        except Exception as exc:
            try:
                self.logger.debug('Audit append skipped: %s', exc)
            except Exception:
                pass

        # In fast/test mode we may still want deterministic AB assignment for
        # unit tests. If requested via ASSIGN_SYNC_FOR_TESTS, run the same
        # assign loop inline so tests observing assignment can assert it.
        try:
            sync_assign = os.getenv('ASSIGN_SYNC_FOR_TESTS', '0').lower() in {'1','true','yes'}
        except Exception:
            sync_assign = False
        if sync_assign:
            try:
                from src.repositories import ab_test_repo as _ab_repo  # type: ignore
                from src.core.ab.shadow_runner import assign_if_enabled as _assign_if_enabled  # type: ignore
                try:
                    active = await _ab_repo.list_active()
                    for t in (active or []):
                        tid = t.get('id')
                        if not tid:
                            continue
                        try:
                            await _assign_if_enabled(tid, event['id'], tenant_id)
                        except Exception:
                            continue
                except Exception:
                    pass
            except Exception:
                pass
