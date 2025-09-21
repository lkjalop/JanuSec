"""
Test suite for the Pragmatic Security Threat Sifting Platform
Author: Security Engineering Team
Version: 1.0.0
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, AsyncMock
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from main import SecurityOrchestrator
from modules.baseline import BaselineModule
from modules.regex_engine import RegexPatternMatcher
from modules.adaptive_tuner import AdaptiveTuner


@pytest.fixture
def sample_event():
    """Sample event for testing"""
    return {
        'id': 'test-event-001',
        'timestamp': time.time(),
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'process_name': 'chrome.exe',
        'command_line': 'chrome.exe --new-window',
        'event_type': 'process_start'
    }


@pytest.fixture
def mock_config():
    """Mock configuration for testing"""
    return Mock(get=Mock(return_value={}))


class TestBaselineModule:
    """Test baseline module functionality"""
    
    @pytest.mark.asyncio
    async def test_baseline_initialization(self, mock_config):
        """Test baseline module initializes correctly"""
        baseline = BaselineModule(mock_config)
        await baseline.initialize()
        
        # Should have loaded some indicators
        assert len(baseline.known_bad_ips) > 0 or len(baseline.known_bad_domains) > 0
    
    @pytest.mark.asyncio
    async def test_baseline_check_performance(self, mock_config, sample_event):
        """Test baseline check meets performance requirements"""
        baseline = BaselineModule(mock_config)
        await baseline.initialize()
        
        start_time = time.perf_counter()
        result = await baseline.check(sample_event)
        end_time = time.perf_counter()
        
        # Should complete in under 5ms for testing (1ms in production)
        processing_time = (end_time - start_time) * 1000
        assert processing_time < 5.0
        
        # Should return valid result
        assert result is not None
        assert hasattr(result, 'confidence')
        assert 0.0 <= result.confidence <= 1.0
        assert isinstance(result.factors, list)
    
    @pytest.mark.asyncio
    async def test_baseline_malicious_ip_detection(self, mock_config):
        """Test detection of malicious IP addresses"""
        baseline = BaselineModule(mock_config)
        await baseline.initialize()
        
        # Create event with known bad IP
        malicious_event = {
            'id': 'test-malicious',
            'src_ip': '185.220.101.1',  # Sample malicious IP from baseline
            'timestamp': time.time()
        }
        
        result = await baseline.check(malicious_event)
        
        # Should detect as suspicious/malicious
        assert result.confidence > 0.5
        assert any('baseline:known_bad_ip' in factor for factor in result.factors)


class TestRegexEngine:
    """Test regex pattern matching engine"""
    
    @pytest.mark.asyncio
    async def test_regex_initialization(self, mock_config):
        """Test regex engine initializes with patterns"""
        regex_engine = RegexPatternMatcher(mock_config)
        await regex_engine.initialize()
        
        # Should have loaded patterns
        assert len(regex_engine.patterns) > 0
        assert len(regex_engine.patterns_by_category) > 0
    
    @pytest.mark.asyncio
    async def test_regex_timeout_protection(self, mock_config):
        """Test regex timeout protection works"""
        regex_engine = RegexPatternMatcher(mock_config)
        await regex_engine.initialize()
        
        # Create event with lots of content
        large_event = {
            'id': 'test-large',
            'command_line': 'a' * 10000,  # Large string
            'timestamp': time.time()
        }
        
        start_time = time.perf_counter()
        result = await regex_engine.analyze_event(large_event)
        end_time = time.perf_counter()
        
        # Should complete within timeout bounds
        processing_time = (end_time - start_time) * 1000
        assert processing_time < 100.0  # Should be well under global timeout
    
    @pytest.mark.asyncio
    async def test_regex_pattern_matching(self, mock_config):
        """Test regex patterns match expected content"""
        regex_engine = RegexPatternMatcher(mock_config)
        await regex_engine.initialize()
        
        # Create event with suspicious PowerShell command
        suspicious_event = {
            'id': 'test-suspicious',
            'command_line': 'powershell.exe -e ZABlAGMAaABvACAAIgBIAGUAbABsAG8AIABXAG8AcgBsAGQAIgA=',
            'process_name': 'powershell.exe',
            'timestamp': time.time()
        }
        
        result = await regex_engine.analyze_event(suspicious_event)
        
        # Should detect PowerShell obfuscation
        assert result.confidence_delta > 0
        assert len(result.matches) > 0
        assert any('T1059' in factor for factor in result.factors)


class TestAdaptiveTuner:
    """Test adaptive tuning functionality"""
    
    @pytest.mark.asyncio
    async def test_adaptive_tuner_initialization(self, mock_config):
        """Test adaptive tuner initializes ML models"""
        tuner = AdaptiveTuner(mock_config)
        await tuner.initialize()
        
        # Should have initialized ML models
        assert tuner.anomaly_detector is not None
        assert tuner.pattern_clusterer is not None
    
    @pytest.mark.asyncio
    async def test_drift_detection(self, mock_config):
        """Test drift detection with sample data"""
        tuner = AdaptiveTuner(mock_config)
        await tuner.initialize()
        
        # Add sample decisions to history
        for i in range(100):
            sample_decision = Mock()
            sample_decision.confidence = 0.5 + (i % 10) * 0.05  # Varying confidence
            sample_decision.verdict = 'benign' if i % 2 == 0 else 'suspicious'
            sample_decision.processing_time_ms = 1.0 + (i % 5) * 0.1
            sample_decision.factors = ['baseline:test']
            
            await tuner.record_decision(sample_decision)
        
        # Run tuning cycle
        results = await tuner.run_tuning_cycle()
        
        # Should complete without errors
        assert results is not None
        assert hasattr(results, 'drift_detected')
        assert isinstance(results.recommendations, list)


class TestPerformanceRequirements:
    """Test performance requirements are met"""
    
    @pytest.mark.asyncio
    async def test_end_to_end_latency(self, mock_config, sample_event):
        """Test end-to-end processing latency"""
        # Mock external dependencies to focus on core performance
        orchestrator = SecurityOrchestrator()
        orchestrator.xdr_connector = AsyncMock()
        
        # This would test the full orchestrator, but we need to implement more modules first
        # For now, just test that it can be instantiated
        assert orchestrator is not None


class TestIntegrationPoints:
    """Test integration capabilities"""
    
    @pytest.mark.asyncio
    async def test_xdr_integration_mock(self, mock_config):
        """Test XDR integration (mocked)"""
        from adapters.eclipse_xdr import EclipseXDRConnector
        
        connector = EclipseXDRConnector(mock_config)
        await connector.initialize()
        
        # Test verdict update
        result = await connector.update_verdict('test-event', 'malicious', 0.95)
        assert result is True  # Should succeed with mock


# Performance benchmarks
class TestPerformanceBenchmarks:
    """Performance benchmarks to ensure SLA compliance"""
    
    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_baseline_processing_benchmark(self, mock_config):
        """Benchmark baseline processing speed"""
        baseline = BaselineModule(mock_config)
        await baseline.initialize()
        
        events = []
        for i in range(1000):
            events.append({
                'id': f'bench-{i}',
                'src_ip': f'192.168.1.{i % 255}',
                'timestamp': time.time()
            })
        
        start_time = time.perf_counter()
        
        for event in events:
            await baseline.check(event)
        
        end_time = time.perf_counter()
        
        total_time = (end_time - start_time) * 1000  # Convert to ms
        avg_time = total_time / len(events)
        
        print(f"\nBaseline benchmark: {len(events)} events in {total_time:.1f}ms")
        print(f"Average per event: {avg_time:.3f}ms")
        
        # Should average under 1ms per event
        assert avg_time < 1.0


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "--tb=short"])