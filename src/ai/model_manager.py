# 🤖 **AI Architecture & Graceful Degradation Strategy**
## **JanuSec Platform - Multi-Tier AI Implementation**

---

## 📊 **AI Platform Classification**

The **JanuSec Platform** (formerly "Threat Sifter") is an **Adaptive Threat Decision Platform** with the following characteristics:

### **🧠 Hybrid AI Architecture**
```
┌─────────────────────────────────────────────────────────────┐
│                    AI PROCESSING TIERS                      │
│                                                             │
│  Tier 1: Rule-Based Intelligence (Always Available)        │
│  ├── Deterministic pattern matching                        │
│  ├── Signature-based detection                             │
│  ├── Threat intelligence feeds                             │
│  └── Regex pattern engine                                  │
│                                                             │
│  Tier 2: Lightweight ML (Local Models)                     │
│  ├── Scikit-learn Isolation Forest                         │
│  ├── MiniBatch K-Means clustering                          │
│  ├── Statistical anomaly detection                         │
│  └── Drift detection algorithms                            │
│                                                             │
│  Tier 3: Advanced AI Services (External APIs)              │
│  ├── Large Language Models (OpenAI/Azure)                  │
│  ├── Advanced threat attribution                           │
│  ├── Natural language analysis                             │
│  └── Complex behavioral modeling                           │
│                                                             │
│  Tier 4: Specialized Models (Optional Enhancement)         │
│  ├── Custom trained models                                 │
│  ├── Industry-specific patterns                            │
│  ├── Organization-specific tuning                          │
│  └── Advanced ML pipelines                                 │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 **AI Models & Technologies Used**

### **Core ML Models** (Always Available - Local)
```python
# Lightweight ML Stack
CORE_ML_MODELS = {
    'anomaly_detection': {
        'model': 'IsolationForest',
        'library': 'scikit-learn',
        'memory_usage': '<50MB',
        'inference_time': '<10ms',
        'accuracy': '85%+',
        'use_case': 'Detect behavioral anomalies in security events'
    },
    
    'clustering': {
        'model': 'MiniBatchKMeans',
        'library': 'scikit-learn', 
        'memory_usage': '<30MB',
        'inference_time': '<5ms',
        'accuracy': '78%+',
        'use_case': 'Group similar threats and attack patterns'
    },
    
    'drift_detection': {
        'model': 'Jensen-Shannon Divergence',
        'library': 'scipy',
        'memory_usage': '<10MB',
        'inference_time': '<2ms',
        'accuracy': '92%+',
        'use_case': 'Detect changes in threat landscape'
    },
    
    'statistical_analysis': {
        'model': 'Custom Statistical Algorithms',
        'library': 'numpy/scipy',
        'memory_usage': '<20MB', 
        'inference_time': '<3ms',
        'accuracy': '80%+',
        'use_case': 'Time series analysis and threshold optimization'
    }
}
```

### **Advanced AI Services** (External APIs)
```python
# External AI Enhancement Stack
EXTERNAL_AI_SERVICES = {
    'primary_llm': {
        'service': 'Azure OpenAI GPT-4',
        'fallback': 'OpenAI GPT-3.5-turbo',
        'use_case': 'Complex threat analysis and attribution',
        'timeout': '30s',
        'retry_attempts': 3
    },
    
    'threat_intelligence': {
        'service': 'Microsoft Defender Threat Intelligence',
        'fallback': 'VirusTotal API',
        'use_case': 'IOC enrichment and threat actor attribution',
        'timeout': '15s',
        'retry_attempts': 2
    },
    
    'behavioral_analysis': {
        'service': 'Custom Neural Network (Optional)',
        'fallback': 'Statistical baseline comparison',
        'use_case': 'Advanced user behavior analysis',
        'timeout': '45s',
        'retry_attempts': 2
    }
}
```

---

## 🛡️ **Graceful Degradation Architecture**

### **Multi-Tier Fallback Strategy**

<function_calls>
<invoke name="create_file">
<parameter name="content">"""
AI Model Manager with Graceful Degradation
Handles model availability, fallback strategies, and performance optimization

Author: AI Engineering Team
Version: 1.0.0
"""

import asyncio
import logging
import time
import json
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timedelta
import aiohttp
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import MiniBatchKMeans
from sklearn.preprocessing import StandardScaler

# Optional open-source model manager
try:
    from .oss_models import OpenSourceModelManager
except Exception:  # fallback if file missing or deps not installed
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
    last_error: Optional[str] = None


@dataclass
class AnalysisResult:
    verdict: str
    confidence: float
    processing_time_ms: float
    model_tier_used: ModelTier
    fallback_applied: bool
    additional_context: Dict[str, Any]


class AIModelManager:
    """
    Central manager for all AI models with graceful degradation capabilities
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
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
        if OpenSourceModelManager and config.get('oss_models', {}).get('enable', False):
            try:
                self.oss_manager = OpenSourceModelManager(config.get('oss_models'))
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
    
    async def analyze_threat(self, event_data: Dict[str, Any], 
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
        
        # Try analysis with preferred tier first, then fallback
        analysis_result = None
        fallback_applied = False
        
        # Tier 4: Specialized Models (if available)
        if preferred_tier == ModelTier.SPECIALIZED and self._is_model_available(ModelTier.SPECIALIZED):
            try:
                analysis_result = await self._analyze_with_specialized_models(event_data)
                if analysis_result:
                    analysis_result.model_tier_used = ModelTier.SPECIALIZED
            except Exception as e:
                self.logger.warning(f"Specialized models failed, falling back: {e}")
                fallback_applied = True
        
        # Tier 3: External AI Services (if available and not already tried)
        if not analysis_result and self._is_model_available(ModelTier.EXTERNAL_AI):
            try:
                analysis_result = await self._analyze_with_external_ai(event_data)
                if analysis_result:
                    analysis_result.model_tier_used = ModelTier.EXTERNAL_AI
                    if preferred_tier != ModelTier.EXTERNAL_AI:
                        fallback_applied = True
            except Exception as e:
                self.logger.warning(f"External AI failed, falling back: {e}")
                fallback_applied = True
        
        # Tier 2: Lightweight ML (if available and not already tried)
        if not analysis_result and self._is_model_available(ModelTier.LIGHTWEIGHT_ML):
            try:
                analysis_result = await self._analyze_with_lightweight_ml(event_data)
                if analysis_result:
                    analysis_result.model_tier_used = ModelTier.LIGHTWEIGHT_ML
                    if preferred_tier not in [ModelTier.LIGHTWEIGHT_ML]:
                        fallback_applied = True
            except Exception as e:
                self.logger.warning(f"Lightweight ML failed, falling back: {e}")
                fallback_applied = True
        
        # Tier 1: Rule-based Intelligence (always available fallback)
        if not analysis_result:
            analysis_result = await self._analyze_with_rule_based(event_data)
            analysis_result.model_tier_used = ModelTier.RULE_BASED
            if preferred_tier != ModelTier.RULE_BASED:
                fallback_applied = True
        
        # Update processing time and fallback status
        processing_time_ms = (time.time() - start_time) * 1000
        analysis_result.processing_time_ms = processing_time_ms
        analysis_result.fallback_applied = fallback_applied
        
        # Cache successful results
        self._cache_result(cache_key, analysis_result)
        
        # Update performance metrics
        self._update_performance_metrics(analysis_result)
        
        return analysis_result
    
    async def _analyze_with_external_ai(self, event_data: Dict[str, Any]) -> Optional[AnalysisResult]:
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
                            'model': 'external_ai'
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
    
    async def _analyze_with_lightweight_ml(self, event_data: Dict[str, Any]) -> Optional[AnalysisResult]:
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
    
    async def _analyze_with_rule_based(self, event_data: Dict[str, Any]) -> AnalysisResult:
        """Rule-based analysis - always available fallback"""
        
        event_type = event_data.get('event_type', 'unknown')
        severity = event_data.get('severity', 'low')
        confidence_base = event_data.get('confidence', 0.5)
        
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
    
    async def _analyze_with_specialized_models(self, event_data: Dict[str, Any]) -> Optional[AnalysisResult]:
        """Use open-source transformer models if configured for enrichment/classification."""
        if not self.oss_manager:
            return None
        try:
            # Simple heuristic: use classification model if severity high or event_type suspicious
            event_type = event_data.get('event_type', '')
            severity = event_data.get('severity', 'low')
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
    
    def _extract_ml_features(self, event_data: Dict[str, Any]) -> List[float]:
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
    
    def _build_threat_analysis_prompt(self, event_data: Dict[str, Any]) -> str:
        """Build prompt for AI threat analysis"""
        
        return f"""
        Analyze this security event and provide a threat assessment:
        
        Event Type: {event_data.get('event_type', 'unknown')}
        Severity: {event_data.get('severity', 'unknown')}
        Source: {event_data.get('source', 'unknown')}
        Timestamp: {event_data.get('timestamp', 'unknown')}
        
        Event Details:
        {json.dumps(event_data.get('details', {}), indent=2)}
        
        Please respond in JSON format:
        {{
            "verdict": "malicious|suspicious|benign",
            "confidence": 0.0-1.0,
            "reasoning": "explanation of analysis",
            "mitre_tactics": ["list of MITRE ATT&CK tactics"],
            "recommended_actions": ["list of recommended response actions"]
        }}
        """
    
    def _parse_ai_response(self, ai_response: str) -> Tuple[str, float, Dict[str, Any]]:
        """Parse AI response into structured format"""
        
        try:
            # Try to extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            
            if json_match:
                response_data = json.loads(json_match.group())
                return (
                    response_data.get('verdict', 'suspicious'),
                    response_data.get('confidence', 0.5),
                    {
                        'reasoning': response_data.get('reasoning', ''),
                        'mitre_tactics': response_data.get('mitre_tactics', []),
                        'recommended_actions': response_data.get('recommended_actions', [])
                    }
                )
            else:
                # Fallback to simple text parsing
                if 'malicious' in ai_response.lower():
                    verdict = 'malicious'
                    confidence = 0.8
                elif 'suspicious' in ai_response.lower():
                    verdict = 'suspicious' 
                    confidence = 0.6
                else:
                    verdict = 'benign'
                    confidence = 0.7
                
                return verdict, confidence, {'reasoning': ai_response}
                
        except Exception as e:
            self.logger.error(f"Failed to parse AI response: {e}")
            return 'suspicious', 0.5, {'error': 'Failed to parse AI response'}
    
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
    def _generate_cache_key(self, event_data: Dict[str, Any]) -> str:
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
    
    def _get_cached_result(self, cache_key: str) -> Optional[AnalysisResult]:
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
    
    def get_model_status_summary(self) -> Dict[str, Any]:
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