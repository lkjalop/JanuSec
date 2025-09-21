"""
Adaptive Tuner - Automatically optimizes patterns, thresholds, and model parameters
Author: Security Engineering Team
Version: 1.0.0

Handles drift detection, pattern optimization, threshold calibration, and lightweight ML tuning.
Integrates open-source models for enhanced pattern recognition and anomaly detection.
"""

import asyncio
import logging
import numpy as np
import time
import json
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import deque, defaultdict
from datetime import datetime, timedelta

# Lightweight ML models
from sklearn.ensemble import IsolationForest
from sklearn.cluster import MiniBatchKMeans
from sklearn.preprocessing import StandardScaler
from scipy.stats import entropy
from scipy.spatial.distance import jensenshannon


@dataclass
class TuningRecommendation:
    """A specific tuning recommendation with confidence and risk assessment"""
    type: str  # 'threshold_adjustment', 'pattern_optimization', 'model_retrain'
    component: str  # Which component to adjust
    current_value: Any
    recommended_value: Any
    confidence: float
    expected_improvement: float
    risk_level: str  # 'low', 'medium', 'high'
    justification: str
    timestamp: float


@dataclass
class TuningResults:
    """Results from a tuning cycle"""
    cycle_id: str
    timestamp: float
    recommendations: List[TuningRecommendation]
    has_recommendations: bool
    summary: str
    drift_detected: bool
    performance_metrics: Dict[str, float]


@dataclass
class DriftMetrics:
    """Metrics for detecting system drift"""
    confidence_distribution_shift: float
    pattern_performance_change: float
    error_rate_change: float
    processing_time_change: float
    overall_drift_score: float


class AdaptiveTuner:
    """
    Automatically optimizes patterns, thresholds, and model parameters.
    Detects drift and recommends adjustments with confidence scoring.
    """

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Historical data storage
        self.confidence_history = deque(maxlen=10000)  # Last 10k decisions
        self.pattern_performance = defaultdict(lambda: deque(maxlen=1000))
        self.processing_time_history = deque(maxlen=5000)
        self.error_rate_history = deque(maxlen=1000)
        
        # Drift detection
        self.baseline_metrics = None
        self.last_calibration = 0
        self.drift_threshold = 0.15  # Jensen-Shannon divergence threshold
        
        # Lightweight ML models for anomaly detection
        self.anomaly_detector = None
        self.pattern_clusterer = None
        self.scaler = StandardScaler()
        
        # Recommendation storage
        self.pending_recommendations = []
        self.applied_recommendations = []
        
        # Performance tracking
        self.tuning_cycles_run = 0
        self.successful_optimizations = 0
        self.optimization_success_rate = 0.0

    async def initialize(self):
        """Initialize the adaptive tuner"""
        self.logger.info("Initializing adaptive tuner...")
        
        # Initialize lightweight ML models
        self.anomaly_detector = IsolationForest(
            contamination=0.1,  # Expect 10% anomalies
            random_state=42,
            n_jobs=-1
        )
        
        self.pattern_clusterer = MiniBatchKMeans(
            n_clusters=20,  # Start with 20 pattern clusters
            random_state=42,
            batch_size=100
        )
        
        # Load historical data if available
        await self._load_historical_data()
        
        self.logger.info("Adaptive tuner initialized successfully")

    async def record_decision(self, decision_result):
        """Record a decision for adaptive learning"""
        # Extract features for ML models
        features = self._extract_decision_features(decision_result)
        
        # Store in history
        self.confidence_history.append({
            'confidence': decision_result.confidence,
            'verdict': decision_result.verdict,
            'processing_time': decision_result.processing_time_ms,
            'factors': decision_result.factors,
            'timestamp': time.time(),
            'features': features
        })
        
        # Record pattern performance
        for factor in decision_result.factors:
            if factor.startswith(('regex:', 'pattern:')):
                self.pattern_performance[factor].append({
                    'confidence_contribution': self._estimate_confidence_contribution(factor, decision_result),
                    'processing_time': decision_result.processing_time_ms,
                    'timestamp': time.time()
                })
        
        # Record processing time
        self.processing_time_history.append({
            'time_ms': decision_result.processing_time_ms,
            'timestamp': time.time()
        })
        
        # Periodic model updates
        if len(self.confidence_history) % 100 == 0:
            await self._update_ml_models()

    async def run_tuning_cycle(self) -> TuningResults:
        """Run a complete tuning cycle with drift detection and optimization"""
        cycle_id = f"cycle_{int(time.time())}"
        self.tuning_cycles_run += 1
        
        self.logger.info(f"Starting adaptive tuning cycle: {cycle_id}")
        
        try:
            # 1. Detect drift
            drift_metrics = await self._detect_drift()
            
            # 2. Analyze performance patterns
            performance_analysis = await self._analyze_performance()
            
            # 3. Generate recommendations
            recommendations = await self._generate_recommendations(drift_metrics, performance_analysis)
            
            # 4. Create tuning results
            results = TuningResults(
                cycle_id=cycle_id,
                timestamp=time.time(),
                recommendations=recommendations,
                has_recommendations=len(recommendations) > 0,
                summary=self._create_summary(recommendations, drift_metrics),
                drift_detected=drift_metrics.overall_drift_score > self.drift_threshold,
                performance_metrics=performance_analysis
            )
            
            # 5. Log results
            self.logger.info(f"Tuning cycle {cycle_id} complete. "
                           f"Recommendations: {len(recommendations)}, "
                           f"Drift detected: {results.drift_detected}")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error in tuning cycle {cycle_id}: {e}")
            return TuningResults(
                cycle_id=cycle_id,
                timestamp=time.time(),
                recommendations=[],
                has_recommendations=False,
                summary=f"Tuning cycle failed: {e}",
                drift_detected=False,
                performance_metrics={}
            )

    async def _detect_drift(self) -> DriftMetrics:
        """Detect system drift across multiple dimensions"""
        if len(self.confidence_history) < 100:
            return DriftMetrics(0, 0, 0, 0, 0)  # Not enough data
        
        # Confidence distribution drift
        recent_confidences = [d['confidence'] for d in list(self.confidence_history)[-500:]]
        older_confidences = [d['confidence'] for d in list(self.confidence_history)[-1000:-500]]
        
        confidence_drift = 0
        if len(older_confidences) > 50:
            confidence_drift = self._calculate_distribution_shift(older_confidences, recent_confidences)
        
        # Pattern performance drift
        pattern_drift = await self._calculate_pattern_performance_drift()
        
        # Error rate drift
        error_drift = await self._calculate_error_rate_drift()
        
        # Processing time drift
        time_drift = await self._calculate_processing_time_drift()
        
        # Overall drift score (weighted average)
        overall_drift = (
            0.4 * confidence_drift + 
            0.3 * pattern_drift + 
            0.2 * error_drift + 
            0.1 * time_drift
        )
        
        return DriftMetrics(
            confidence_distribution_shift=confidence_drift,
            pattern_performance_change=pattern_drift,
            error_rate_change=error_drift,
            processing_time_change=time_drift,
            overall_drift_score=overall_drift
        )

    def _calculate_distribution_shift(self, old_data: List[float], new_data: List[float]) -> float:
        """Calculate Jensen-Shannon divergence between distributions"""
        if len(old_data) < 10 or len(new_data) < 10:
            return 0.0
        
        try:
            # Create histograms
            bins = np.linspace(0, 1, 11)  # 0.0, 0.1, 0.2, ..., 1.0
            old_hist, _ = np.histogram(old_data, bins=bins, density=True)
            new_hist, _ = np.histogram(new_data, bins=bins, density=True)
            
            # Normalize to probabilities
            old_hist = old_hist / np.sum(old_hist) + 1e-10  # Add small epsilon
            new_hist = new_hist / np.sum(new_hist) + 1e-10
            
            # Calculate Jensen-Shannon divergence
            return jensenshannon(old_hist, new_hist)
            
        except Exception as e:
            self.logger.warning(f"Error calculating distribution shift: {e}")
            return 0.0

    async def _calculate_pattern_performance_drift(self) -> float:
        """Calculate drift in pattern performance"""
        if not self.pattern_performance:
            return 0.0
        
        total_drift = 0
        pattern_count = 0
        
        for pattern, history in self.pattern_performance.items():
            if len(history) < 20:
                continue
            
            # Compare recent vs older performance
            recent = [h['confidence_contribution'] for h in list(history)[-10:]]
            older = [h['confidence_contribution'] for h in list(history)[-20:-10]]
            
            if len(recent) >= 5 and len(older) >= 5:
                recent_avg = np.mean(recent)
                older_avg = np.mean(older)
                
                # Calculate relative change
                if older_avg > 0:
                    drift = abs(recent_avg - older_avg) / older_avg
                    total_drift += drift
                    pattern_count += 1
        
        return total_drift / pattern_count if pattern_count > 0 else 0.0

    async def _calculate_error_rate_drift(self) -> float:
        """Calculate drift in error rates"""
        if len(self.confidence_history) < 100:
            return 0.0
        
        # Count errors in recent vs older decisions
        recent_decisions = list(self.confidence_history)[-500:]
        older_decisions = list(self.confidence_history)[-1000:-500]
        
        recent_errors = sum(1 for d in recent_decisions if 'error' in d.get('factors', []))
        older_errors = sum(1 for d in older_decisions if 'error' in d.get('factors', []))
        
        recent_error_rate = recent_errors / len(recent_decisions)
        older_error_rate = older_errors / len(older_decisions) if older_decisions else recent_error_rate
        
        # Return relative change
        if older_error_rate > 0:
            return abs(recent_error_rate - older_error_rate) / older_error_rate
        return 0.0

    async def _calculate_processing_time_drift(self) -> float:
        """Calculate drift in processing times"""
        if len(self.processing_time_history) < 100:
            return 0.0
        
        recent_times = [h['time_ms'] for h in list(self.processing_time_history)[-250:]]
        older_times = [h['time_ms'] for h in list(self.processing_time_history)[-500:-250]]
        
        if not older_times:
            return 0.0
        
        recent_avg = np.mean(recent_times)
        older_avg = np.mean(older_times)
        
        # Return relative change
        if older_avg > 0:
            return abs(recent_avg - older_avg) / older_avg
        return 0.0

    async def _analyze_performance(self) -> Dict[str, float]:
        """Analyze overall system performance"""
        if len(self.confidence_history) < 50:
            return {}
        
        recent_decisions = list(self.confidence_history)[-500:]
        
        # Calculate performance metrics
        metrics = {
            'avg_confidence': np.mean([d['confidence'] for d in recent_decisions]),
            'avg_processing_time': np.mean([d['processing_time'] for d in recent_decisions]),
            'benign_rate': len([d for d in recent_decisions if d['verdict'] == 'benign']) / len(recent_decisions),
            'malicious_rate': len([d for d in recent_decisions if d['verdict'] == 'malicious']) / len(recent_decisions),
            'suspicious_rate': len([d for d in recent_decisions if d['verdict'] == 'suspicious']) / len(recent_decisions),
        }
        
        # Pattern efficiency analysis
        pattern_efficiency = await self._analyze_pattern_efficiency()
        metrics.update(pattern_efficiency)
        
        return metrics

    async def _analyze_pattern_efficiency(self) -> Dict[str, float]:
        """Analyze efficiency of regex patterns and other detectors"""
        if not self.pattern_performance:
            return {}
        
        efficient_patterns = 0
        inefficient_patterns = 0
        total_patterns = 0
        
        for pattern, history in self.pattern_performance.items():
            if len(history) < 10:
                continue
            
            total_patterns += 1
            recent_performance = list(history)[-10:]
            
            avg_confidence = np.mean([h['confidence_contribution'] for h in recent_performance])
            avg_time = np.mean([h['processing_time'] for h in recent_performance])
            
            # Pattern is efficient if it contributes good confidence without taking too much time
            if avg_confidence > 0.1 and avg_time < 5.0:  # >0.1 confidence, <5ms
                efficient_patterns += 1
            elif avg_confidence < 0.05 or avg_time > 10.0:  # <0.05 confidence or >10ms
                inefficient_patterns += 1
        
        return {
            'pattern_efficiency_rate': efficient_patterns / total_patterns if total_patterns > 0 else 0,
            'inefficient_pattern_rate': inefficient_patterns / total_patterns if total_patterns > 0 else 0,
            'total_patterns_analyzed': total_patterns
        }

    async def _generate_recommendations(self, drift_metrics: DriftMetrics, performance_metrics: Dict[str, float]) -> List[TuningRecommendation]:
        """Generate tuning recommendations based on analysis"""
        recommendations = []
        
        # Threshold adjustment recommendations
        threshold_recs = await self._generate_threshold_recommendations(performance_metrics)
        recommendations.extend(threshold_recs)
        
        # Pattern optimization recommendations
        pattern_recs = await self._generate_pattern_recommendations(drift_metrics)
        recommendations.extend(pattern_recs)
        
        # Model retraining recommendations
        model_recs = await self._generate_model_recommendations(drift_metrics, performance_metrics)
        recommendations.extend(model_recs)
        
        return recommendations

    async def _generate_threshold_recommendations(self, metrics: Dict[str, float]) -> List[TuningRecommendation]:
        """Generate threshold adjustment recommendations"""
        recommendations = []
        
        # Check if too many events are going to suspicious (inefficient)
        if metrics.get('suspicious_rate', 0) > 0.3:  # >30% suspicious
            recommendations.append(TuningRecommendation(
                type='threshold_adjustment',
                component='confidence_thresholds',
                current_value={'benign': 0.1, 'malicious': 0.9},
                recommended_value={'benign': 0.15, 'malicious': 0.85},
                confidence=0.7,
                expected_improvement=0.1,
                risk_level='low',
                justification=f"Suspicious rate ({metrics['suspicious_rate']:.1%}) is too high, adjust thresholds to reduce uncertainty",
                timestamp=time.time()
            ))
        
        # Check if processing time is too high
        if metrics.get('avg_processing_time', 0) > 100:  # >100ms average
            recommendations.append(TuningRecommendation(
                type='threshold_adjustment',
                component='timeout_limits',
                current_value={'regex_timeout': 10, 'analysis_timeout': 200},
                recommended_value={'regex_timeout': 8, 'analysis_timeout': 150},
                confidence=0.6,
                expected_improvement=0.15,
                risk_level='medium',
                justification=f"Average processing time ({metrics['avg_processing_time']:.1f}ms) is high, reduce timeouts",
                timestamp=time.time()
            ))
        
        return recommendations

    async def _generate_pattern_recommendations(self, drift_metrics: DriftMetrics) -> List[TuningRecommendation]:
        """Generate pattern optimization recommendations"""
        recommendations = []
        
        # Identify poorly performing patterns
        for pattern, history in self.pattern_performance.items():
            if len(history) < 20:
                continue
            
            recent_performance = list(history)[-10:]
            avg_confidence = np.mean([h['confidence_contribution'] for h in recent_performance])
            avg_time = np.mean([h['processing_time'] for h in recent_performance])
            
            # Pattern takes too long with low contribution
            if avg_time > 5.0 and avg_confidence < 0.05:
                recommendations.append(TuningRecommendation(
                    type='pattern_optimization',
                    component=pattern,
                    current_value='current_regex_pattern',
                    recommended_value='optimized_regex_pattern',
                    confidence=0.8,
                    expected_improvement=0.2,
                    risk_level='low',
                    justification=f"Pattern {pattern} has high latency ({avg_time:.1f}ms) with low contribution ({avg_confidence:.3f})",
                    timestamp=time.time()
                ))
        
        return recommendations

    async def _generate_model_recommendations(self, drift_metrics: DriftMetrics, performance_metrics: Dict[str, float]) -> List[TuningRecommendation]:
        """Generate ML model retraining recommendations"""
        recommendations = []
        
        # Recommend retraining if significant drift detected
        if drift_metrics.overall_drift_score > 0.2:
            recommendations.append(TuningRecommendation(
                type='model_retrain',
                component='anomaly_detector',
                current_value='current_model_state',
                recommended_value='retrained_model',
                confidence=0.9,
                expected_improvement=0.25,
                risk_level='medium',
                justification=f"Significant drift detected (score: {drift_metrics.overall_drift_score:.3f}), model retraining recommended",
                timestamp=time.time()
            ))
        
        return recommendations

    def _create_summary(self, recommendations: List[TuningRecommendation], drift_metrics: DriftMetrics) -> str:
        """Create a human-readable summary of tuning results"""
        if not recommendations:
            return f"No recommendations. System stable (drift score: {drift_metrics.overall_drift_score:.3f})"
        
        summary_parts = []
        
        # Group recommendations by type
        rec_by_type = defaultdict(int)
        for rec in recommendations:
            rec_by_type[rec.type] += 1
        
        for rec_type, count in rec_by_type.items():
            summary_parts.append(f"{count} {rec_type.replace('_', ' ')} recommendation{'s' if count > 1 else ''}")
        
        summary = ", ".join(summary_parts)
        summary += f". Overall drift score: {drift_metrics.overall_drift_score:.3f}"
        
        return summary

    async def _update_ml_models(self):
        """Update lightweight ML models with recent data"""
        if len(self.confidence_history) < 100:
            return
        
        try:
            # Prepare feature matrix
            features = []
            for decision in list(self.confidence_history)[-500:]:  # Last 500 decisions
                feature_vector = decision.get('features', [])
                if feature_vector:
                    features.append(feature_vector)
            
            if len(features) < 50:
                return
            
            # Convert to numpy array and scale
            X = np.array(features)
            X_scaled = self.scaler.fit_transform(X)
            
            # Update anomaly detector
            self.anomaly_detector.fit(X_scaled)
            
            # Update pattern clusterer
            self.pattern_clusterer.partial_fit(X_scaled)
            
            self.logger.debug(f"Updated ML models with {len(features)} samples")
            
        except Exception as e:
            self.logger.warning(f"Error updating ML models: {e}")

    def _extract_decision_features(self, decision_result) -> List[float]:
        """Extract numerical features from decision result for ML models"""
        features = [
            decision_result.confidence,
            decision_result.processing_time_ms / 1000.0,  # Convert to seconds
            len(decision_result.factors),
            1.0 if decision_result.verdict == 'benign' else 0.0,
            1.0 if decision_result.verdict == 'malicious' else 0.0,
            1.0 if decision_result.verdict == 'suspicious' else 0.0,
        ]
        
        # Add factor-based features
        factor_categories = ['regex:', 'network:', 'endpoint:', 'attack:', 'behavior:']
        for category in factor_categories:
            count = sum(1 for factor in decision_result.factors if factor.startswith(category))
            features.append(count)
        
        return features

    def _estimate_confidence_contribution(self, factor: str, decision_result) -> float:
        """Estimate how much a specific factor contributed to confidence"""
        # Simple heuristic - could be improved with more sophisticated attribution
        base_contribution = 0.1  # Base contribution per factor
        
        # Adjust based on factor type
        if factor.startswith('attack:'):
            return base_contribution * 2.0  # Attack indicators are more important
        elif factor.startswith('regex:'):
            return base_contribution * 1.5  # Regex patterns are moderately important
        elif factor.startswith('baseline:'):
            return base_contribution * 1.2  # Baseline matches are reliable
        
        return base_contribution

    async def _load_historical_data(self):
        """Load historical tuning data if available"""
        try:
            # This would load from persistent storage in a real implementation
            # For now, just initialize empty
            pass
        except Exception as e:
            self.logger.warning(f"Could not load historical data: {e}")

    async def queue_for_approval(self, recommendation: TuningRecommendation):
        """Queue a recommendation for manual approval"""
        self.pending_recommendations.append(recommendation)
        self.logger.info(f"Recommendation queued for approval: {recommendation.type} on {recommendation.component}")

    async def apply_recommendation(self, recommendation: TuningRecommendation) -> bool:
        """Apply a tuning recommendation"""
        try:
            # This would interface with the actual components
            # For now, just log and mark as applied
            self.applied_recommendations.append(recommendation)
            self.successful_optimizations += 1
            
            self.logger.info(f"Applied recommendation: {recommendation.type} on {recommendation.component}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to apply recommendation: {e}")
            return False

    async def shutdown(self):
        """Shutdown the adaptive tuner"""
        self.logger.info("Shutting down adaptive tuner...")
        
        # Calculate final success rate
        if self.tuning_cycles_run > 0:
            self.optimization_success_rate = self.successful_optimizations / self.tuning_cycles_run
        
        # Save final state (would persist to storage in real implementation)
        self.logger.info(f"Adaptive tuner shutdown complete. "
                        f"Success rate: {self.optimization_success_rate:.1%}, "
                        f"Cycles run: {self.tuning_cycles_run}")