"""
Baseline Module - Deterministic pattern matching and threat intelligence lookups
Author: Security Engineering Team
Version: 1.0.0

Provides fast, deterministic filtering using hash tables, bloom filters, and known indicators.
Serves as failsafe that works even when all AI systems are down.
Target: <1ms p95 processing time.
"""

import asyncio
import logging
import time
import hashlib
import json
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict
import ipaddress
import re

# Efficient data structures
from pybloom_live import BloomFilter
import mmh3  # Fast hashing


@dataclass
class BaselineResult:
    """Result from baseline pattern matching"""
    confidence: float
    factors: List[str]
    terminal: bool  # True if this result is definitive
    disposition: Optional[str] = None
    processing_time: float = 0.0
    matched_indicators: List[Dict[str, Any]] = None


@dataclass
class ThreatIndicator:
    """A threat intelligence indicator"""
    value: str
    type: str  # 'ip', 'domain', 'hash', 'url'
    confidence: float
    source: str
    last_seen: float
    tags: List[str]


class BaselineModule:
    """
    Deterministic filtering & cheap confidence seeding.
    Uses efficient data structures for O(1) lookups against known indicators.
    """

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Fast lookup structures
        self.malicious_ips = BloomFilter(capacity=1000000, error_rate=0.001)
        self.malicious_domains = BloomFilter(capacity=500000, error_rate=0.001)
        self.malicious_hashes = BloomFilter(capacity=2000000, error_rate=0.001)
        self.benign_patterns = BloomFilter(capacity=100000, error_rate=0.001)
        
        # Exact match sets for high-confidence indicators
        self.known_bad_ips: Set[str] = set()
        self.known_bad_domains: Set[str] = set()
        self.known_bad_hashes: Set[str] = set()
        self.known_good_patterns: Set[str] = set()
        
        # Pattern frequency tracking for learning
        self.pattern_frequencies = defaultdict(int)
        self.false_positive_patterns = defaultdict(int)
        
        # Performance metrics
        self.lookups_performed = 0
        self.cache_hits = 0
        self.processing_times = []
        
        # Pre-compiled regex for common patterns
        self.ip_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.domain_regex = re.compile(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
        self.hash_regex = {
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b')
        }

    async def initialize(self):
        """Initialize baseline module with threat intelligence data"""
        self.logger.info("Initializing baseline module...")
        
        # Load threat intelligence indicators
        await self._load_threat_indicators()
        
        # Load benign patterns from historical data
        await self._load_benign_patterns()
        
        self.logger.info(f"Baseline module initialized. "
                        f"Loaded {len(self.known_bad_ips)} known bad IPs, "
                        f"{len(self.known_bad_domains)} known bad domains, "
                        f"{len(self.known_bad_hashes)} known bad hashes")

    async def check(self, event: Dict[str, Any]) -> BaselineResult:
        """
        Main baseline check - fast deterministic analysis.
        Returns confidence score and factors within <1ms target.
        """
        start_time = time.perf_counter()
        self.lookups_performed += 1
        
        try:
            factors = []
            confidence = 0.0
            matched_indicators = []
            
            # Extract indicators from event
            indicators = self._extract_indicators(event)
            
            # Check against known bad indicators
            for indicator_type, values in indicators.items():
                for value in values:
                    result = await self._check_indicator(indicator_type, value)
                    if result:
                        factors.extend(result['factors'])
                        confidence = max(confidence, result['confidence'])
                        matched_indicators.append(result['indicator'])
            
            # Check for known benign patterns
            benign_confidence = await self._check_benign_patterns(event)
            if benign_confidence > 0:
                factors.append('baseline:known_benign')
                confidence = max(0, confidence - benign_confidence)
            
            # Apply heuristic adjustments
            confidence = self._apply_heuristics(event, confidence, factors)
            
            # Determine if terminal decision
            terminal = confidence >= 0.95 or confidence <= 0.05
            disposition = None
            if terminal:
                if confidence >= 0.95:
                    disposition = 'malicious'
                elif confidence <= 0.05:
                    disposition = 'benign'
            
            processing_time = (time.perf_counter() - start_time) * 1000  # Convert to ms
            self.processing_times.append(processing_time)
            
            return BaselineResult(
                confidence=confidence,
                factors=factors,
                terminal=terminal,
                disposition=disposition,
                processing_time=processing_time,
                matched_indicators=matched_indicators
            )
            
        except Exception as e:
            self.logger.error(f"Error in baseline check: {e}")
            processing_time = (time.perf_counter() - start_time) * 1000
            
            return BaselineResult(
                confidence=0.5,  # Neutral when we can't determine
                factors=['baseline:processing_error'],
                terminal=False,
                processing_time=processing_time
            )

    def _extract_indicators(self, event: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract IOCs from event data"""
        indicators = {
            'ips': [],
            'domains': [],
            'hashes': [],
            'urls': []
        }
        
        # Convert event to searchable text
        text_content = json.dumps(event).lower()
        
        # Extract IP addresses
        ip_matches = self.ip_regex.findall(text_content)
        for ip_str in ip_matches:
            try:
                # Validate IP address
                ip = ipaddress.ip_address(ip_str)
                if not ip.is_private and not ip.is_loopback:
                    indicators['ips'].append(ip_str)
            except ValueError:
                continue
        
        # Extract domain names
        domain_matches = self.domain_regex.findall(text_content)
        for domain in domain_matches:
            if self._is_valid_domain(domain):
                indicators['domains'].append(domain.lower())
        
        # Extract hashes
        for hash_type, regex in self.hash_regex.items():
            hash_matches = regex.findall(text_content)
            indicators['hashes'].extend([h.lower() for h in hash_matches])
        
        # Extract specific fields if they exist
        for field in ['src_ip', 'dst_ip', 'domain', 'file_hash', 'process_hash']:
            if field in event and event[field]:
                if 'ip' in field:
                    indicators['ips'].append(str(event[field]))
                elif field == 'domain':
                    indicators['domains'].append(str(event[field]).lower())
                elif 'hash' in field:
                    indicators['hashes'].append(str(event[field]).lower())
        
        # Remove duplicates
        for key in indicators:
            indicators[key] = list(set(indicators[key]))
        
        return indicators

    async def _check_indicator(self, indicator_type: str, value: str) -> Optional[Dict[str, Any]]:
        """Check a specific indicator against threat intelligence"""
        confidence = 0.0
        factors = []
        
        if indicator_type == 'ips':
            if value in self.known_bad_ips:
                confidence = 0.9
                factors.append('baseline:known_bad_ip')
            elif value in self.malicious_ips:
                confidence = 0.7
                factors.append('baseline:suspicious_ip')
        
        elif indicator_type == 'domains':
            if value in self.known_bad_domains:
                confidence = 0.9
                factors.append('baseline:known_bad_domain')
            elif value in self.malicious_domains:
                confidence = 0.7
                factors.append('baseline:suspicious_domain')
            
            # Check for suspicious TLD patterns
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw']
            if any(value.endswith(tld) for tld in suspicious_tlds):
                confidence = max(confidence, 0.3)
                factors.append('baseline:suspicious_tld')
        
        elif indicator_type == 'hashes':
            if value in self.known_bad_hashes:
                confidence = 0.95
                factors.append('baseline:known_malware_hash')
            elif value in self.malicious_hashes:
                confidence = 0.8
                factors.append('baseline:suspicious_hash')
        
        if confidence > 0:
            return {
                'confidence': confidence,
                'factors': factors,
                'indicator': {
                    'type': indicator_type,
                    'value': value,
                    'confidence': confidence
                }
            }
        
        return None

    async def _check_benign_patterns(self, event: Dict[str, Any]) -> float:
        """Check for known benign patterns"""
        benign_confidence = 0.0
        
        # Check specific fields for benign indicators
        if 'process_name' in event:
            process_name = str(event['process_name']).lower()
            
            # Known benign processes
            benign_processes = {
                'explorer.exe', 'chrome.exe', 'firefox.exe', 'notepad.exe',
                'winword.exe', 'excel.exe', 'outlook.exe', 'teams.exe'
            }
            
            if process_name in benign_processes:
                benign_confidence = max(benign_confidence, 0.2)
        
        # Check for internal IP patterns
        if 'src_ip' in event:
            try:
                ip = ipaddress.ip_address(event['src_ip'])
                if ip.is_private:
                    benign_confidence = max(benign_confidence, 0.1)
            except ValueError:
                pass
        
        # Check domain reputation for high-reputation domains
        if 'domain' in event:
            domain = str(event['domain']).lower()
            high_reputation_domains = {
                'microsoft.com', 'google.com', 'apple.com', 'amazon.com',
                'cloudflare.com', 'github.com', 'stackoverflow.com'
            }
            
            if any(domain.endswith(trusted) for trusted in high_reputation_domains):
                benign_confidence = max(benign_confidence, 0.3)
        
        return benign_confidence

    def _apply_heuristics(self, event: Dict[str, Any], confidence: float, factors: List[str]) -> float:
        """Apply heuristic adjustments to confidence"""
        adjusted_confidence = confidence
        
        # Time-based heuristics
        if 'timestamp' in event:
            try:
                event_time = float(event['timestamp'])
                hour = time.localtime(event_time).tm_hour
                
                # Slightly more suspicious during non-business hours
                if hour < 7 or hour > 19:  # Outside 7 AM - 7 PM
                    adjusted_confidence *= 1.05
            except (ValueError, TypeError):
                pass
        
        # Frequency-based adjustments
        event_signature = self._create_event_signature(event)
        if event_signature in self.pattern_frequencies:
            frequency = self.pattern_frequencies[event_signature]
            
            # Very frequent patterns are less suspicious (unless they're known bad)
            if frequency > 100 and confidence < 0.8:
                adjusted_confidence *= 0.9
            
            # Check if this pattern has been marked as false positive
            if event_signature in self.false_positive_patterns:
                fp_count = self.false_positive_patterns[event_signature]
                if fp_count > 5:  # Multiple false positives
                    adjusted_confidence *= 0.8
        
        # Multi-factor adjustments
        factor_count = len([f for f in factors if not f.startswith('baseline:processing')])
        if factor_count > 3:  # Multiple indicators
            adjusted_confidence *= 1.1
        
        return min(1.0, max(0.0, adjusted_confidence))

    def _create_event_signature(self, event: Dict[str, Any]) -> str:
        """Create a signature for the event for frequency tracking"""
        # Use key fields to create a signature
        signature_fields = ['src_ip', 'dst_ip', 'process_name', 'domain', 'event_type']
        
        signature_parts = []
        for field in signature_fields:
            if field in event and event[field]:
                signature_parts.append(f"{field}:{event[field]}")
        
        if not signature_parts:
            # Fallback to hash of entire event
            event_str = json.dumps(event, sort_keys=True)
            return hashlib.md5(event_str.encode()).hexdigest()[:16]
        
        return "|".join(signature_parts)

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain name format"""
        if len(domain) > 253 or len(domain) < 3:
            return False
        
        if domain.startswith('.') or domain.endswith('.'):
            return False
        
        # Must have at least one dot
        if '.' not in domain:
            return False
        
        # Check for valid characters
        if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
            return False
        
        return True

    async def learn_benign(self, event: Dict[str, Any]):
        """Learn from confirmed benign events"""
        signature = self._create_event_signature(event)
        self.known_good_patterns.add(signature)
        
        # Add to bloom filter for fast lookup
        self.benign_patterns.add(signature)

    async def learn_false_positive(self, event: Dict[str, Any]):
        """Learn from false positive events"""
        signature = self._create_event_signature(event)
        self.false_positive_patterns[signature] += 1

    async def quick_check(self, event: Dict[str, Any]) -> BaselineResult:
        """Ultra-fast check for timeout scenarios"""
        # Simplified check with minimal processing
        indicators = self._extract_indicators(event)
        
        confidence = 0.0
        factors = []
        
        # Only check exact matches for speed
        for ip in indicators['ips']:
            if ip in self.known_bad_ips:
                confidence = 0.9
                factors.append('baseline:known_bad_ip')
                break
        
        for domain in indicators['domains']:
            if domain in self.known_bad_domains:
                confidence = 0.9
                factors.append('baseline:known_bad_domain')
                break
        
        return BaselineResult(
            confidence=confidence,
            factors=factors,
            terminal=confidence >= 0.9,
            disposition='malicious' if confidence >= 0.9 else None,
            processing_time=0.5  # Estimated quick processing time
        )

    async def _load_threat_indicators(self):
        """Load threat intelligence indicators from various sources"""
        # In a real implementation, this would load from:
        # - Commercial threat intel feeds
        # - Open source feeds (abuse.ch, etc.)
        # - Internal IOC databases
        
        # For demo, load some sample indicators
        sample_bad_ips = [
            '185.220.101.1', '185.220.102.1', '192.42.116.1'
        ]
        
        sample_bad_domains = [
            'malware-example.com', 'phishing-site.tk', 'bad-domain.ml'
        ]
        
        sample_bad_hashes = [
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'd41d8cd98f00b204e9800998ecf8427e'
        ]
        
        # Add to both exact match sets and bloom filters
        for ip in sample_bad_ips:
            self.known_bad_ips.add(ip)
            self.malicious_ips.add(ip)
        
        for domain in sample_bad_domains:
            self.known_bad_domains.add(domain)
            self.malicious_domains.add(domain)
        
        for hash_val in sample_bad_hashes:
            self.known_bad_hashes.add(hash_val)
            self.malicious_hashes.add(hash_val)

    async def _load_benign_patterns(self):
        """Load known benign patterns from historical data"""
        # Sample benign patterns
        sample_patterns = [
            'process_name:explorer.exe|src_ip:192.168.1.100',
            'domain:microsoft.com|process_name:winword.exe'
        ]
        
        for pattern in sample_patterns:
            self.known_good_patterns.add(pattern)
            self.benign_patterns.add(pattern)

    async def health_check(self) -> bool:
        """Check module health"""
        try:
            # Test basic functionality
            test_event = {
                'id': 'health_check',
                'src_ip': '127.0.0.1',
                'timestamp': time.time()
            }
            
            result = await self.check(test_event)
            return result.processing_time < 5.0  # Health check should be fast
            
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return False

    async def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        if not self.processing_times:
            return {}
        
        return {
            'total_lookups': self.lookups_performed,
            'cache_hits': self.cache_hits,
            'avg_processing_time': sum(self.processing_times) / len(self.processing_times),
            'p95_processing_time': sorted(self.processing_times)[int(len(self.processing_times) * 0.95)],
            'known_bad_indicators': {
                'ips': len(self.known_bad_ips),
                'domains': len(self.known_bad_domains),
                'hashes': len(self.known_bad_hashes)
            }
        }

    async def shutdown(self):
        """Shutdown baseline module"""
        self.logger.info("Shutting down baseline module...")
        
        # Save learned patterns in a real implementation
        stats = await self.get_performance_stats()
        self.logger.info(f"Baseline module shutdown. Final stats: {stats}")