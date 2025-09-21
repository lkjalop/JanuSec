"""
Decision Engine - Centralized routing and confidence calculation logic
Author: Security Engineering Team
Version: 1.0.0
"""

import asyncio
import logging
from typing import Dict, Any
from dataclasses import dataclass


@dataclass
class RoutingDecision:
    """Routing decision with justification"""
    path: str  # 'benign', 'malicious', 'deep'
    confidence: float
    factors: list
    reason: str
    

class DecisionEngine:
    """Centralized routing and confidence calculation logic"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Load thresholds from config
        self.benign_threshold = config.get('confidence', {}).get('benign_threshold', 0.1)
        self.malicious_threshold = config.get('confidence', {}).get('malicious_threshold', 0.9)
    
    async def initialize(self):
        """Initialize decision engine"""
        self.logger.info("Decision engine initialized")
    
    async def make_decision(self, pipeline_result) -> RoutingDecision:
        """Make routing decision based on confidence"""
        confidence = pipeline_result.confidence
        
        if confidence >= self.malicious_threshold:
            return RoutingDecision(
                path='malicious',
                confidence=confidence,
                factors=pipeline_result.factors,
                reason=f"High confidence malicious ({confidence:.2f})"
            )
        elif confidence <= self.benign_threshold:
            return RoutingDecision(
                path='benign',
                confidence=confidence,
                factors=pipeline_result.factors,
                reason=f"Low confidence benign ({confidence:.2f})"
            )
        else:
            return RoutingDecision(
                path='deep',
                confidence=confidence,
                factors=pipeline_result.factors,
                reason=f"Uncertain - needs deep analysis ({confidence:.2f})"
            )
    
    async def finalize_decision(self, analysis_result):
        """Finalize decision after deep analysis"""
        return analysis_result
    
    async def update_thresholds(self, new_thresholds: Dict[str, float]):
        """Update confidence thresholds"""
        self.benign_threshold = new_thresholds.get('benign', self.benign_threshold)
        self.malicious_threshold = new_thresholds.get('malicious', self.malicious_threshold)
        self.logger.info(f"Updated thresholds: benign={self.benign_threshold}, malicious={self.malicious_threshold}")
    
    async def shutdown(self):
        """Shutdown decision engine"""
        self.logger.info("Decision engine shutdown")