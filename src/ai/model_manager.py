"""AI model manager with graceful degradation and provider selection."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
import numpy as np
from sklearn.cluster import MiniBatchKMeans
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from core.metrics.cost_ledger import get_cost_ledger
from core.finops.finops_manager import get_finops_manager

try:
    from .oss_models import OpenSourceModelManager
except ImportError:  # pragma: no cover
    OpenSourceModelManager = None

class ModelTier(Enum):
    RULE_BASED = "rule_based"
    LIGHTWEIGHT_ML = "lightweight_ml" 
    EXTERNAL_AI = "external_ai"
    SPECIALIZED = "specialized"


class ModelStatus(Enum):
    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    MAINTENANCE = "maintenance"


@dataclass
class ModelHealth:
    tier: ModelTier
    model_name: str
    status: ModelStatus
    last_check: float
    response_time_ms: float
    success_rate: float
    error_count: int
    last_error: str | None = None


@dataclass
class AnalysisResult:
    verdict: str
    confidence: float
    processing_time_ms: float
    model_tier_used: ModelTier
    fallback_applied: bool
    additional_context: dict[str, Any]


class AIModelManager:
    """
    Central manager for all AI models with graceful degradation capabilities
    """
    
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)

        oss_cfg: dict[str, Any] = {}
        if isinstance(config, dict):
            oss_cfg = dict(config.get('oss_models', {}))
        else:
            try:
                oss_cfg = dict(config.get('oss_models') or {})
            except Exception:
                oss_cfg = {}
        self.oss_config = oss_cfg
        backend = (oss_cfg.get('backend') or 'transformers').lower()
        device = (oss_cfg.get('device') or 'cpu').lower()
        self.oss_config['backend'] = backend
        self.oss_config['device'] = device
        self.oss_config.setdefault('ollama_root', 'D:/Ollama')
        self.oss_config.setdefault('ollama_host', 'http://127.0.0.1:11434')
        self.oss_config.setdefault('ollama_cmd', None)
        if 'enable' not in self.oss_config:
            self.oss_config['enable'] = bool(self.oss_config.get('enable') or self.oss_config.get('enable_oss_models'))
        self.oss_backend = self.oss_config['backend']
        self.oss_device = self.oss_config['device']

        # Model health tracking
        self.model_health = {}
        self.performance_history = []
        
        # Caching layers
        self.result_cache = {}  # In-memory cache
        self.cache_ttl = config.get('cache_ttl_seconds', 300)
        self.max_cache_size = config.get('max_cache_size', 10000)
        
        # Circuit breakers for external services
        self.circuit_breakers = {}
        
        # Local ML models
        self.isolation_forest = None
        self.kmeans_cluster = None
        self.scaler = None
        
        # External AI session
        self.ai_session = None

        # Optional OSS model manager (specialized tier)
        self.oss_manager = None
        if OpenSourceModelManager and self.oss_config.get('enable'):
            try:
                self.oss_manager = OpenSourceModelManager(self.oss_config)
                self._update_model_health(ModelTier.SPECIALIZED, 'oss_models', ModelStatus.AVAILABLE, 0, 100.0)
            except Exception as e:
                self._update_model_health(ModelTier.SPECIALIZED, 'oss_models', ModelStatus.UNAVAILABLE, 0, 0.0, str(e))
        
        # Initialize models
        asyncio.create_task(self.initialize_models())
    
    async def initialize_models(self):
        """Initialize all AI models and health monitoring"""
        
        # Initialize local ML models
        try:
            self.isolation_forest = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            self.kmeans_cluster = MiniBatchKMeans(
                n_clusters=10,
                random_state=42,
                batch_size=100
            )
            self.scaler = StandardScaler()
            
            # Train with synthetic data for bootstrapping
            await self._bootstrap_ml_models()
            
            self._update_model_health(ModelTier.LIGHTWEIGHT_ML, 'isolation_forest', 
                                    ModelStatus.AVAILABLE, 0, 100.0)
            
            self.logger.info("Local ML models initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize local ML models: {e}")
            self._update_model_health(ModelTier.LIGHTWEIGHT_ML, 'isolation_forest',
                                    ModelStatus.UNAVAILABLE, 0, 0.0, str(e))
        
        # Initialize external AI session
        try:
            self.ai_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                headers={'User-Agent': 'ThreatSifter/1.0'}
            )
            
            # Test external AI connectivity
            await self._test_external_ai_health()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize external AI session: {e}")
    
    async def analyze_threat(self, event_data: dict[str, Any], 
                           preferred_tier: ModelTier = ModelTier.EXTERNAL_AI) -> AnalysisResult:
        """
        Analyze threat using best available AI model with graceful degradation
        """
        
        start_time = time.time()
        cache_key = self._generate_cache_key(event_data)
        
        # Check cache first
        cached_result = self._get_cached_result(cache_key)
        if cached_result:
            self.logger.debug("Returning cached analysis result")
            return cached_result

        # Check FinOps budget gates (simple guard): if closed, prefer local tiers
        fm = get_finops_manager()
        budget_closed = False
        try:
            # Very lightweight heuristic: if latest hourly cost exceeds EWMA threshold, treat as closed when block flag is set
            # In demo, limits are stored under integrations ai.config.limits via integrations_endpoints
            from api.integrations_endpoints import _STATE as _INTEG_STATE  # type: ignore
            limits = ((_INTEG_STATE.get('ai') or {}).get('config') or {}).get('limits') or {}
            block_on_exceed = bool(limits.get('block_on_exceed'))
            if block_on_exceed:
                ov = fm.hourly_summary(None)
                hours = (ov.get('hours') or [])
                if hours:
                    # Treat any cost spike over 95th percentile of last window as closed (demo heuristic)
                    vals = [h.get('cost_units', 0.0) for h in hours][-24:]
                    import numpy as _np
                    p95 = float(_np.percentile(vals, 95)) if vals else 0.0
                    if (vals and vals[-1] > p95 and p95 > 0):
                        budget_closed = True
        except Exception:
            budget_closed = False

        # Try analysis with preferred tier first, then fallback (respecting budget)
        analysis_result = None
        fallback_applied = False
        ledger = get_cost_ledger()
        
        # Tier 4: Specialized Models (if available)
        if preferred_tier == ModelTier.SPECIALIZED and self._is_model_available(ModelTier.SPECIALIZED):
            try:
                t0 = time.perf_counter()
                analysis_result = await self._analyze_with_specialized_models(event_data)
                if analysis_result:
                    analysis_result.model_tier_used = ModelTier.SPECIALIZED
                    ledger.record('specialized','oss_models', t0, tokens=0, cached=False, success=True)
            except Exception as e:
                self.logger.warning(f"Specialized models failed, falling back: {e}")
                fallback_applied = True
        
        # Tier 3: External AI Services (if available and not already tried)
        if not analysis_result and (not budget_closed) and self._is_model_available(ModelTier.EXTERNAL_AI):
            try:
                t0 = time.perf_counter()
                analysis_result = await self._analyze_with_external_ai(event_data)
                if analysis_result:
                    analysis_result.model_tier_used = ModelTier.EXTERNAL_AI
                    if preferred_tier != ModelTier.EXTERNAL_AI:
                        fallback_applied = True
                    # Record token usage (if present) and optional tenant for real-time cost linkage
                    toks = 0
                    try:
                        toks = int((analysis_result.additional_context or {}).get('tokens_used') or 0)
                    except Exception:
                        toks = 0
                    tenant = (event_data.get('tenant') or event_data.get('tenant_id') or 'default') if isinstance(event_data, dict) else 'default'
                    ledger.record('external_ai','primary', t0, tokens=toks, cached=False, success=True, tenant=tenant)
            except Exception as e:
                self.logger.warning(f"External AI failed, falling back: {e}")
                fallback_applied = True
        
        # Tier 2: Lightweight ML (if available and not already tried)
        if not analysis_result and self._is_model_available(ModelTier.LIGHTWEIGHT_ML):
            try:
                t0 = time.perf_counter()
                analysis_result = await self._analyze_with_lightweight_ml(event_data)
                if analysis_result:
                    analysis_result.model_tier_used = ModelTier.LIGHTWEIGHT_ML
                    if preferred_tier not in [ModelTier.LIGHTWEIGHT_ML]:
                        fallback_applied = True
                    tenant = (event_data.get('tenant') or event_data.get('tenant_id') or 'default') if isinstance(event_data, dict) else 'default'
                    ledger.record('lightweight_ml','iforest_kmeans', t0, tokens=0, cached=False, success=True, tenant=tenant)
            except Exception as e:
                self.logger.warning(f"Lightweight ML failed, falling back: {e}")
                fallback_applied = True
        
        # Tier 1: Rule-based Intelligence (always available fallback)
        if not analysis_result:
            t0 = time.perf_counter()
            analysis_result = await self._analyze_with_rule_based(event_data)
            analysis_result.model_tier_used = ModelTier.RULE_BASED
            if preferred_tier != ModelTier.RULE_BASED:
                fallback_applied = True
            tenant = (event_data.get('tenant') or event_data.get('tenant_id') or 'default') if isinstance(event_data, dict) else 'default'
            ledger.record('rule_based','rules', t0, tokens=0, cached=False, success=True, tenant=tenant)
        
        # Update processing time and fallback status
        processing_time_ms = (time.time() - start_time) * 1000
        analysis_result.processing_time_ms = processing_time_ms
        analysis_result.fallback_applied = fallback_applied
        
        # Cache successful results
        self._cache_result(cache_key, analysis_result)
        
        # Update performance metrics
        self._update_performance_metrics(analysis_result)
        
        return analysis_result
    
    async def _analyze_with_external_ai(self, event_data: dict[str, Any]) -> AnalysisResult | None:
        """Analyze using external AI services with circuit breaker"""
        
        service_name = 'external_ai'
        
        # Check circuit breaker
        if self._is_circuit_open(service_name):
            self.logger.warning("Circuit breaker open for external AI service")
            return None
        
        try:
            # Prepare AI prompt
            prompt = self._build_threat_analysis_prompt(event_data)
            
            # Call external AI service (example with OpenAI-compatible API)
            ai_config = self.config.get('external_ai', {})
            
            payload = {
                'messages': [
                    {
                        'role': 'system',
                        'content': 'You are a cybersecurity expert analyzing security events.'
                    },
                    {
                        'role': 'user', 
                        'content': prompt
                    }
                ],
                'temperature': 0.1,  # Low temperature for consistent analysis
                'max_tokens': 500
            }
            
            headers = {
                'Authorization': f"Bearer {ai_config.get('api_key')}",
                'Content-Type': 'application/json'
            }
            
            async with self.ai_session.post(
                ai_config.get('endpoint_url'),
                json=payload,
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    ai_analysis = result['choices'][0]['message']['content']
                    # Optional token usage if provider returns usage metrics
                    tokens_used = 0
                    try:
                        usage = result.get('usage') or {}
                        # prefer total_tokens; else sum prompt+completion
                        if 'total_tokens' in usage:
                            tokens_used = int(usage.get('total_tokens') or 0)
                        else:
                            tokens_used = int((usage.get('prompt_tokens') or 0) + (usage.get('completion_tokens') or 0))
                    except Exception:
                        tokens_used = 0
                    
                    # Parse AI response
                    verdict, confidence, context = self._parse_ai_response(ai_analysis)
                    
                    # Update circuit breaker success
                    self._record_circuit_success(service_name)
                    
                    return AnalysisResult(
                        verdict=verdict,
                        confidence=confidence,
                        processing_time_ms=0,  # Will be set by caller
                        model_tier_used=ModelTier.EXTERNAL_AI,
                        fallback_applied=False,  # Will be set by caller
                        additional_context={
                            'ai_analysis': ai_analysis,
                            'context': context,
                            'model': 'external_ai',
                            'tokens_used': tokens_used
                        }
                    )
                else:
                    error_msg = f"AI API error: {response.status}"
                    self._record_circuit_failure(service_name, error_msg)
                    return None
                    
        except Exception as e:
            self.logger.error(f"External AI analysis failed: {e}")
            self._record_circuit_failure(service_name, str(e))
            return None
    
    async def _analyze_with_lightweight_ml(self, event_data: dict[str, Any]) -> AnalysisResult | None:
        """Analyze using local lightweight ML models"""
        
        try:
            # Extract numerical features from event data
            features = self._extract_ml_features(event_data)
            
            if len(features) < 5:  # Not enough features for ML analysis
                return None
            
            # Anomaly detection using Isolation Forest
            anomaly_score = self.isolation_forest.decision_function([features])[0]
            is_anomaly = self.isolation_forest.predict([features])[0] == -1
            
            # Clustering analysis
            cluster_label = self.kmeans_cluster.predict([features])[0]
            
            # Convert to threat analysis
            if is_anomaly:
                if anomaly_score < -0.5:
                    verdict = "malicious"
                    confidence = min(0.9, abs(anomaly_score))
                else:
                    verdict = "suspicious" 
                    confidence = min(0.7, abs(anomaly_score))
            else:
                verdict = "benign"
                confidence = 0.8
            
            return AnalysisResult(
                verdict=verdict,
                confidence=confidence,
                processing_time_ms=0,  # Will be set by caller
                model_tier_used=ModelTier.LIGHTWEIGHT_ML,
                fallback_applied=False,  # Will be set by caller
                additional_context={
                    'anomaly_score': float(anomaly_score),
                    'cluster_label': int(cluster_label),
                    'features_count': len(features),
                    'model': 'isolation_forest_kmeans'
                }
            )
            
        except Exception as e:
            self.logger.error(f"Lightweight ML analysis failed: {e}")
            return None
    
    async def _analyze_with_rule_based(self, event_data: dict[str, Any]) -> AnalysisResult:
        """Rule-based analysis - always available fallback"""
        
        event_type = event_data.get('event_type', 'unknown')
        severity = event_data.get('severity', 'low')
        event_data.get('confidence', 0.5)
        
        # Simple rule-based logic
        threat_indicators = 0
        threat_context = []
        
        # Check for high-risk event types
        high_risk_types = ['malware_detected', 'lateral_movement', 'data_exfiltration', 
                          'privilege_escalation', 'command_injection']
        if event_type in high_risk_types:
            threat_indicators += 2
            threat_context.append(f"High-risk event type: {event_type}")
        
        # Check severity level
        severity_weights = {'critical': 3, 'high': 2, 'medium': 1, 'low': 0}
        threat_indicators += severity_weights.get(severity, 0)
        if severity in ['critical', 'high']:
            threat_context.append(f"High severity level: {severity}")
        
        # Check for suspicious patterns in event details
        details = event_data.get('details', {})
        suspicious_keywords = ['powershell', 'cmd.exe', 'suspicious', 'malware', 
                             'exploit', 'backdoor', 'trojan', 'ransomware']
        
        for key, value in details.items():
            if isinstance(value, str):
                for keyword in suspicious_keywords:
                    if keyword.lower() in value.lower():
                        threat_indicators += 1
                        threat_context.append(f"Suspicious keyword '{keyword}' in {key}")
        
        # Determine verdict based on indicators
        if threat_indicators >= 4:
            verdict = "malicious"
            confidence = min(0.85, 0.5 + (threat_indicators * 0.1))
        elif threat_indicators >= 2:
            verdict = "suspicious"
            confidence = min(0.75, 0.4 + (threat_indicators * 0.1))
        else:
            verdict = "benign"
            confidence = 0.6
        
        return AnalysisResult(
            verdict=verdict,
            confidence=confidence,
            processing_time_ms=0,  # Will be set by caller
            model_tier_used=ModelTier.RULE_BASED,
            fallback_applied=False,  # Will be set by caller
            additional_context={
                'threat_indicators': threat_indicators,
                'threat_context': threat_context,
                'rule_based_analysis': True,
                'model': 'rule_based_engine'
            }
        )
    
    async def _analyze_with_specialized_models(self, event_data: dict[str, Any]) -> AnalysisResult | None:
        """Use open-source transformer models if configured for enrichment/classification."""
        if not self.oss_manager:
            return None
        try:
            # Simple heuristic: use classification model if severity high or event_type suspicious
            event_data.get('event_type', '')
            event_data.get('severity', 'low')
            text_blob = str(event_data.get('details', {}))[:1000]

            cls_model = self.oss_manager.config.get('default_classification_model', 'roberta_cls')
            emb_model = self.oss_manager.config.get('default_embedding_model', 'roberta_embed')

            classification = await self.oss_manager.classify(cls_model, text_blob)
            embedding = await self.oss_manager.embed(emb_model, text_blob) if classification else None

            if not classification:
                return None

            # Derive verdict from top probability index (placeholder mapping)
            probs = classification['probabilities']
            top_p = max(probs)
            idx = classification['predicted_index']
            # Simple mapping: higher index => more suspicious (demo purpose)
            if top_p > 0.9 and idx >= 2:
                verdict = 'malicious'
                confidence = min(0.9, top_p)
            elif top_p > 0.7 and idx >= 1:
                verdict = 'suspicious'
                confidence = min(0.75, top_p)
            else:
                verdict = 'benign'
                confidence = 0.6

            return AnalysisResult(
                verdict=verdict,
                confidence=confidence,
                processing_time_ms=0,
                model_tier_used=ModelTier.SPECIALIZED,
                fallback_applied=False,
                additional_context={
                    'classification': classification,
                    'embedding_dim': len(embedding) if embedding else 0,
                    'model_ids': {
                        'classification': cls_model,
                        'embedding': emb_model
                    }
                }
            )
        except Exception as e:
            self.logger.error(f"Specialized OSS model analysis failed: {e}")
            return None
    
    def _extract_ml_features(self, event_data: dict[str, Any]) -> list[float]:
        """Extract numerical features for ML analysis"""
        
        features = []
        
        # Basic event features
        severity_map = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        features.append(severity_map.get(event_data.get('severity', 'low'), 1))
        
        features.append(event_data.get('confidence', 0.5))
        features.append(len(str(event_data.get('details', {}))))
        
        # Time-based features
        timestamp = event_data.get('timestamp')
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                features.append(dt.hour)  # Hour of day
                features.append(dt.weekday())  # Day of week
            except:
                features.extend([12, 3])  # Default values
        else:
            features.extend([12, 3])
        
        # Event type encoding (simple hash-based)
        event_type = event_data.get('event_type', 'unknown')
        features.append(hash(event_type) % 1000 / 1000.0)
        
        # Source encoding
        source = event_data.get('source', 'unknown')
        features.append(hash(source) % 1000 / 1000.0)
        
        # Details complexity features
        details = event_data.get('details', {})
        features.append(len(details))
        features.append(len(json.dumps(details)))
        
        return features
    
    def _sanitize_prompt_input(self, text: Any, max_length: int = 1000) -> str:
        """Sanitize arbitrary user/content text before placing into prompts.

        - Coerce to str and truncate to max_length (prevents stuffing)
        - Strip common role/instruction markers (prompt-injection hints)
        - Remove attempt to set roles (system:, assistant:, human:)
        - Normalize whitespace
        """
        import re as _re
        try:
            s = str(text if text is not None else "")
        except Exception:
            s = ""

        if len(s) > max_length:
            s = s[:max_length]

        # Block known injection phrasings and role prefaces
        blocked = [
            r"(?i)\bignore\s+(previous|all)\s+instructions\b",
            r"(?i)\bdisregard\s+(previous|all)\s+instructions\b",
            r"(?i)\boverride\s+system\s+prompt\b",
            r"(?i)\bas\s+an\s+assistant,?\b",
            r"(?i)\bsystem\s*:\s*",
            r"(?i)\bassistant\s*:\s*",
            r"(?i)\bhuman\s*:\s*",
            r"(?i)\btool\s*:\s*",
        ]
        for pat in blocked:
            s = _re.sub(pat, "", s)

        # Normalize whitespace
        s = " ".join(s.split())
        return s

    def _sanitize_nested(self, value: Any, max_leaf: int = 300) -> Any:
        """Recursively sanitize dict/list/string leaves for prompt safety."""
        if isinstance(value, dict):
            return {self._sanitize_prompt_input(k): self._sanitize_nested(v, max_leaf) for k, v in value.items()}
        if isinstance(value, list):
            return [self._sanitize_nested(v, max_leaf) for v in value]
        if isinstance(value, (str, int, float, bool)) or value is None:
            return self._sanitize_prompt_input(value, max_leaf)
        # Fallback to string coercion
        return self._sanitize_prompt_input(value, max_leaf)

    def _build_threat_analysis_prompt(self, event_data: dict[str, Any]) -> str:
        """Build structured prompt for AI threat analysis with injection defenses."""

        ev_type = self._sanitize_prompt_input(event_data.get('event_type', 'unknown'), 120)
        sev = self._sanitize_prompt_input(event_data.get('severity', 'unknown'), 60)
        src = self._sanitize_prompt_input(event_data.get('source', 'unknown'), 120)
        ts = self._sanitize_prompt_input(event_data.get('timestamp', 'unknown'), 120)
        details = self._sanitize_nested(event_data.get('details', {}) or {})

        try:
            details_json = json.dumps(details, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            details_json = "{}"

        return (
            "You are a cybersecurity analyst. Assess the following event.\n"
            "Use only the content within the BEGIN/END markers.\n"
            "Respond strictly in JSON schema described. Do not include prose.\n\n"
            f"BEGIN_EVENT_META\n"
            f"event_type={ev_type}\n"
            f"severity={sev}\n"
            f"source={src}\n"
            f"timestamp={ts}\n"
            f"END_EVENT_META\n\n"
            f"BEGIN_EVENT_DETAILS_JSON\n{details_json}\nEND_EVENT_DETAILS_JSON\n\n"
            "RESPONSE_SCHEMA:\n"
            "{\n"
            "  \"verdict\": \"malicious|suspicious|benign\",\n"
            "  \"confidence\": 0.0-1.0,\n"
            "  \"reasoning\": \"short explanation\",\n"
            "  \"mitre_tactics\": [\"TAxxxx\"],\n"
            "  \"recommended_actions\": [\"action\"]\n"
            "}\n"
        )
    
    def _parse_ai_response(self, ai_response: str) -> tuple[str, float, dict[str, Any]]:
        """Parse and validate AI response using a strict schema with sanitization."""
        try:
            import re
            import html
            from typing import Literal
            from pydantic import BaseModel, Field, ValidationError, field_validator

            class ThreatAnalysisResponse(BaseModel):  # type: ignore[misc]
                verdict: Literal['malicious', 'suspicious', 'benign']
                confidence: float = Field(ge=0.0, le=1.0)
                reasoning: str = Field(default="", max_length=2000)
                mitre_tactics: list[str] = Field(default_factory=list, max_items=20)
                recommended_actions: list[str] = Field(default_factory=list, max_items=20)

                @field_validator('reasoning')
                @classmethod
                def _sanitize_reasoning(cls, v: str) -> str:  # noqa: N805
                    return html.escape(v or "")[:2000]

                @field_validator('mitre_tactics', 'recommended_actions')
                @classmethod
                def _trim_items(cls, v: list[str]) -> list[str]:  # noqa: N805
                    out: list[str] = []
                    for it in v or []:
                        try:
                            out.append((it or "").strip()[:120])
                        except Exception:
                            continue
                    return out[:20]

            # Extract first JSON object
            json_match = re.search(r"\{[\s\S]*\}", ai_response, re.DOTALL)
            if not json_match:
                # Simple fallback classification
                low = ai_response.lower()
                if 'malicious' in low:
                    return 'malicious', 0.8, {'reasoning': html.escape(ai_response)[:500]}
                if 'suspicious' in low:
                    return 'suspicious', 0.6, {'reasoning': html.escape(ai_response)[:500]}
                return 'benign', 0.7, {'reasoning': html.escape(ai_response)[:500]}

            raw = json_match.group()
            obj = json.loads(raw)
            validated = ThreatAnalysisResponse(**obj)
            ctx: dict[str, Any] = {
                'reasoning': validated.reasoning,
                'mitre_tactics': list(validated.mitre_tactics or []),
                'recommended_actions': list(validated.recommended_actions or []),
            }
            return validated.verdict, float(validated.confidence), ctx

        except ValidationError as ve:  # type: ignore[name-defined]
            self.logger.warning(f"AI response validation failed: {ve}")
            return 'suspicious', 0.5, {'error': 'validation_failed'}
        except Exception as e:
            self.logger.error(f"Failed to parse AI response: {e}")
            return 'suspicious', 0.5, {'error': 'parse_failed'}
    
    # Circuit Breaker Implementation
    def _is_circuit_open(self, service_name: str) -> bool:
        """Check if circuit breaker is open for service"""
        
        breaker = self.circuit_breakers.get(service_name, {
            'failures': 0,
            'last_failure': 0,
            'state': 'closed'  # closed, open, half_open
        })
        
        if breaker['state'] == 'open':
            # Check if cooldown period has passed
            if time.time() - breaker['last_failure'] > 300:  # 5 minute cooldown
                breaker['state'] = 'half_open'
                self.circuit_breakers[service_name] = breaker
                return False
            return True
        
        return False
    
    def _record_circuit_success(self, service_name: str):
        """Record successful service call"""
        
        breaker = self.circuit_breakers.get(service_name, {
            'failures': 0,
            'last_failure': 0,
            'state': 'closed'
        })
        
        breaker['failures'] = 0
        breaker['state'] = 'closed'
        self.circuit_breakers[service_name] = breaker
    
    def _record_circuit_failure(self, service_name: str, error: str):
        """Record service failure and potentially open circuit"""
        
        breaker = self.circuit_breakers.get(service_name, {
            'failures': 0,
            'last_failure': 0,
            'state': 'closed'
        })
        
        breaker['failures'] += 1
        breaker['last_failure'] = time.time()
        
        # Open circuit after 3 failures
        if breaker['failures'] >= 3:
            breaker['state'] = 'open'
            self.logger.warning(f"Circuit breaker opened for {service_name} after {breaker['failures']} failures")
        
        self.circuit_breakers[service_name] = breaker
    
    # Caching Implementation
    def _generate_cache_key(self, event_data: dict[str, Any]) -> str:
        """Generate cache key for event data"""
        
        # Create deterministic hash of key event fields
        import hashlib
        
        key_fields = {
            'event_type': event_data.get('event_type'),
            'severity': event_data.get('severity'),
            'source': event_data.get('source'),
            'details_hash': hash(json.dumps(event_data.get('details', {}), sort_keys=True))
        }
        
        cache_key = hashlib.md5(json.dumps(key_fields, sort_keys=True).encode()).hexdigest()
        return cache_key
    
    def _get_cached_result(self, cache_key: str) -> AnalysisResult | None:
        """Get cached analysis result if available and not expired"""
        
        if cache_key in self.result_cache:
            cached_item = self.result_cache[cache_key]
            
            if time.time() - cached_item['timestamp'] < self.cache_ttl:
                return cached_item['result']
            else:
                # Remove expired item
                del self.result_cache[cache_key]
        
        return None
    
    def _cache_result(self, cache_key: str, result: AnalysisResult):
        """Cache analysis result"""
        
        # Implement LRU-style cache eviction
        if len(self.result_cache) >= self.max_cache_size:
            # Remove oldest items (simple approach)
            oldest_keys = sorted(
                self.result_cache.keys(),
                key=lambda k: self.result_cache[k]['timestamp']
            )[:100]  # Remove oldest 100 items
            
            for old_key in oldest_keys:
                del self.result_cache[old_key]
        
        self.result_cache[cache_key] = {
            'result': result,
            'timestamp': time.time()
        }
    
    # Health Monitoring
    def _is_model_available(self, tier: ModelTier) -> bool:
        """Check if models in tier are available"""
        
        if tier == ModelTier.RULE_BASED:
            return True  # Always available
        
        tier_models = [h for h in self.model_health.values() if h.tier == tier]
        if not tier_models:
            return tier == ModelTier.RULE_BASED  # Fallback to rule-based
        
        # At least one model in tier must be available
        return any(model.status == ModelStatus.AVAILABLE for model in tier_models)
    
    def _update_model_health(self, tier: ModelTier, model_name: str, 
                           status: ModelStatus, response_time_ms: float, 
                           success_rate: float, error_msg: str = None):
        """Update model health status"""
        
        health_key = f"{tier.value}_{model_name}"
        
        self.model_health[health_key] = ModelHealth(
            tier=tier,
            model_name=model_name,
            status=status,
            last_check=time.time(),
            response_time_ms=response_time_ms,
            success_rate=success_rate,
            error_count=self.model_health.get(health_key, ModelHealth(
                tier, model_name, status, 0, 0, 0, 0
            )).error_count + (1 if error_msg else 0),
            last_error=error_msg
        )
    
    def _update_performance_metrics(self, result: AnalysisResult):
        """Update performance metrics"""
        
        self.performance_history.append({
            'timestamp': time.time(),
            'tier': result.model_tier_used.value,
            'processing_time_ms': result.processing_time_ms,
            'confidence': result.confidence,
            'fallback_applied': result.fallback_applied
        })
        
        # Keep only last 1000 metrics
        if len(self.performance_history) > 1000:
            self.performance_history = self.performance_history[-1000:]
    
    async def _bootstrap_ml_models(self):
        """Bootstrap ML models with synthetic training data"""
        
        # Generate synthetic training data for isolation forest
        np.random.seed(42)
        
        # Normal behavior patterns
        normal_features = np.random.normal(0, 1, (1000, 10))
        
        # Anomalous patterns (outliers)  
        anomaly_features = np.random.normal(3, 1, (100, 10))
        
        # Combine training data
        training_data = np.vstack([normal_features, anomaly_features])
        
        # Fit models
        self.isolation_forest.fit(training_data)
        self.kmeans_cluster.fit(training_data)
        self.scaler.fit(training_data)
        
        self.logger.info("ML models bootstrapped with synthetic data")
    
    async def _test_external_ai_health(self):
        """Test external AI service health"""
        
        try:
            # Simple health check request
            test_payload = {
                'messages': [{'role': 'user', 'content': 'Hello'}],
                'max_tokens': 5
            }
            
            ai_config = self.config.get('external_ai', {})
            
            if not ai_config.get('api_key'):
                self.logger.warning("External AI API key not configured")
                self._update_model_health(ModelTier.EXTERNAL_AI, 'health_check',
                                        ModelStatus.UNAVAILABLE, 0, 0.0, "API key not configured")
                return
            
            async with self.ai_session.post(
                ai_config.get('endpoint_url', 'https://api.openai.com/v1/chat/completions'),
                json=test_payload,
                headers={
                    'Authorization': f"Bearer {ai_config.get('api_key')}",
                    'Content-Type': 'application/json'
                },
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                
                if response.status == 200:
                    self._update_model_health(ModelTier.EXTERNAL_AI, 'health_check',
                                            ModelStatus.AVAILABLE, 200, 100.0)
                    self.logger.info("External AI service is healthy")
                else:
                    error_msg = f"HTTP {response.status}"
                    self._update_model_health(ModelTier.EXTERNAL_AI, 'health_check',
                                            ModelStatus.DEGRADED, 1000, 50.0, error_msg)
                    self.logger.warning(f"External AI service degraded: {error_msg}")
                    
        except Exception as e:
            self._update_model_health(ModelTier.EXTERNAL_AI, 'health_check',
                                    ModelStatus.UNAVAILABLE, 0, 0.0, str(e))
            self.logger.error(f"External AI service unavailable: {e}")
    
    def get_model_status_summary(self) -> dict[str, Any]:
        """Get comprehensive model status summary"""
        
        summary = {
            'overall_health': 'healthy',
            'tiers': {},
            'cache_stats': {
                'size': len(self.result_cache),
                'max_size': self.max_cache_size,
                'hit_rate': 0.0  # Would calculate from metrics
            },
            'circuit_breakers': self.circuit_breakers,
            'performance_metrics': {
                'avg_processing_time_ms': 0.0,
                'fallback_rate': 0.0
            }
        }
        
        # Aggregate tier status
        for tier in ModelTier:
            tier_models = [h for h in self.model_health.values() if h.tier == tier]
            
            if tier_models:
                available_count = sum(1 for m in tier_models if m.status == ModelStatus.AVAILABLE)
                avg_response_time = np.mean([m.response_time_ms for m in tier_models])
                avg_success_rate = np.mean([m.success_rate for m in tier_models])
                
                summary['tiers'][tier.value] = {
                    'models_count': len(tier_models),
                    'available_count': available_count,
                    'avg_response_time_ms': float(avg_response_time),
                    'avg_success_rate': float(avg_success_rate),
                    'status': 'available' if available_count > 0 else 'unavailable'
                }
            else:
                summary['tiers'][tier.value] = {
                    'models_count': 0,
                    'available_count': 0,
                    'status': 'not_configured'
                }
        
        # Calculate performance metrics
        if self.performance_history:
            recent_metrics = self.performance_history[-100:]  # Last 100 calls
            avg_time = np.mean([m['processing_time_ms'] for m in recent_metrics])
            fallback_rate = np.mean([m['fallback_applied'] for m in recent_metrics])
            
            summary['performance_metrics'] = {
                'avg_processing_time_ms': float(avg_time),
                'fallback_rate': float(fallback_rate)
            }
        
        # Determine overall health
        tier_statuses = [t['status'] for t in summary['tiers'].values()]
        if any(status == 'available' for status in tier_statuses):
            if 'unavailable' in tier_statuses:
                summary['overall_health'] = 'degraded'
            else:
                summary['overall_health'] = 'healthy'
        else:
            summary['overall_health'] = 'critical'
        
        return summary


# Example configuration for the AI Model Manager
AI_CONFIG = {
    'external_ai': {
        'api_key': 'your_openai_api_key_here',
        'endpoint_url': 'https://api.openai.com/v1/chat/completions',
        'model': 'gpt-3.5-turbo',
        'max_tokens': 500,
        'temperature': 0.1
    },
    'cache_ttl_seconds': 300,  # 5 minutes
    'max_cache_size': 10000,
    'ml_model_retrain_hours': 24,  # Retrain every 24 hours
    'health_check_interval_seconds': 60
}


# Example usage
async def demo_ai_graceful_degradation():
    """Demonstrate AI graceful degradation capabilities"""
    
    ai_manager = AIModelManager(AI_CONFIG)
    await ai_manager.initialize_models()
    
    # Sample threat event
    threat_event = {
        'id': 'demo_threat_001',
        'event_type': 'malware_detected',
        'severity': 'high',
        'confidence': 0.85,
        'source': 'endpoint_agent',
        'timestamp': datetime.utcnow().isoformat(),
        'details': {
            'file_hash': 'a1b2c3d4e5f6...',
            'process_name': 'suspicious.exe',
            'command_line': 'powershell.exe -enc base64_encoded_command'
        }
    }
    
    # Test analysis with different tiers
    print("=== AI Graceful Degradation Demo ===")
    
    # Try with external AI first
    result = await ai_manager.analyze_threat(threat_event, ModelTier.EXTERNAL_AI)
    print(f"Analysis Result: {result.verdict} (confidence: {result.confidence:.2f})")
    print(f"Tier Used: {result.model_tier_used.value}")
    print(f"Fallback Applied: {result.fallback_applied}")
    print(f"Processing Time: {result.processing_time_ms:.1f}ms")
    
    # Get model status
    status = ai_manager.get_model_status_summary()
    print(f"\nOverall Health: {status['overall_health']}")
    print(f"Cache Size: {status['cache_stats']['size']}")
    
    print("=== Demo Complete ===")


if __name__ == "__main__":
    asyncio.run(demo_ai_graceful_degradation())
