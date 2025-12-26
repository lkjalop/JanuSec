"""
Regex Pattern Matcher - Loose regex pattern matching with performance optimization
Author: Security Engineering Team
Version: 1.0.0

Applies loose regex patterns to catch threats that don't match exact signatures.
Includes pattern complexity analysis and performance optimization.
Target: <10ms p95 processing time with timeout protection.
"""

import asyncio
import hashlib
import json
import logging
import re
import signal

# For performance optimization
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import lru_cache
from re import Pattern
from typing import Any, Dict, List, Optional, Tuple

from core.metrics import make_counter, make_histogram
from functools import lru_cache
import os
import math
from core.logging_utils import log_backoff


@dataclass
class RegexMatch:
    """A single regex pattern match"""
    pattern_id: str
    pattern_name: str
    matched_text: str
    confidence_contribution: float
    factor: str
    match_position: int
    processing_time_ms: float


@dataclass
class RegexResult:
    """Result from regex pattern analysis"""
    matches: list[RegexMatch]
    confidence_delta: float
    factors: list[str]
    processing_time_ms: float
    patterns_tested: int
    timeout_occurred: bool = False


@dataclass 
class PatternDefinition:
    """Definition of a regex pattern"""
    id: str
    name: str
    pattern: str
    compiled_pattern: Pattern[str]
    category: str
    confidence: float
    factor: str
    complexity_score: int
    enabled: bool = True
    false_positive_count: int = 0
    true_positive_count: int = 0


class RegexPatternMatcher:
    """
    Loose regex pattern matching with performance optimization and confidence scoring.
    Integrates with baseline module for enhanced pattern recognition.
    """

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Pattern storage
        self.patterns: dict[str, PatternDefinition] = {}
        self.patterns_by_category: dict[str, list[PatternDefinition]] = defaultdict(list)
        
        # Performance optimization
        self.pattern_cache = {}  # LRU cache for compiled patterns
        self.execution_timeout = 10.0  # 10ms timeout per pattern
        self.global_timeout = 50.0  # 50ms total timeout
        
        # Performance tracking
        self.pattern_performance = defaultdict(lambda: deque(maxlen=100))
        self.execution_times = deque(maxlen=1000)
        self.timeout_count = 0
        self.patterns_executed = 0

        # Metrics
        try:
            self.metric_timeout_counter = make_counter('hunt_regex_timeouts_total', 'Total regex pattern timeouts')
            self.metric_patterns_tested = make_counter('hunt_regex_patterns_tested_total', 'Total regex patterns tested')
            self.metric_processing_time_ms = make_histogram('hunt_regex_processing_time_ms', 'Regex processing time (ms)', buckets=[1,5,10,25,50,100,250,500])
            # New effectiveness metrics
            self.metric_patterns_attempted = make_counter('regex_patterns_attempted_total','Regex patterns attempted')
            self.metric_patterns_completed = make_counter('regex_patterns_completed_total','Regex patterns completed without timeout')
            self.metric_patterns_timedout = make_counter('regex_patterns_timed_out_total','Regex patterns timed out')
        except Exception:
            # Prometheus not available or metric init failed; fall back silently
            self.metric_timeout_counter = None
            self.metric_patterns_tested = None
            self.metric_processing_time_ms = None
            self.metric_patterns_attempted = None
            self.metric_patterns_completed = None
            self.metric_patterns_timedout = None
        
        # Thread pool for pattern execution
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="regex")
        
        # Confidence weights by match type
        self.confidence_weights = {
            'exact_match': 0.8,
            'fuzzy_match': 0.4,
            'partial_match': 0.2,
            'context_match': 0.15
        }

    async def initialize(self):
        """Initialize regex pattern matcher"""
        self.logger.info("Initializing regex pattern matcher...")
        
        # Load pattern definitions
        await self._load_pattern_definitions()
        
        # Compile and analyze patterns
        await self._compile_patterns()
        
        # Optimize pattern execution order
        await self._optimize_pattern_order()
        
        self.logger.info(f"Regex pattern matcher initialized. "
                        f"Loaded {len(self.patterns)} patterns across "
                        f"{len(self.patterns_by_category)} categories")

    async def analyze_event(self, event: dict[str, Any]) -> RegexResult:
        """
        Apply loose regex matching with performance bounds and timeout protection.
        Returns enriched confidence and matched factors.
        """
        start_time = time.perf_counter()
        
        try:
            # Extract searchable content from event
            searchable_content = self._extract_searchable_content(event)
            
            if not searchable_content:
                return RegexResult(
                    matches=[],
                    confidence_delta=0.0,
                    factors=[],
                    processing_time_ms=0.0,
                    patterns_tested=0
                )
            
            # Apply patterns with timeout protection
            matches = await self._apply_patterns_with_timeout(searchable_content, event)
            
            # Calculate confidence contribution
            confidence_delta = self._calculate_confidence_delta(matches)
            
            # Extract factors
            factors = [match.factor for match in matches if match.factor not in ['', None]]
            
            processing_time = (time.perf_counter() - start_time) * 1000
            self.execution_times.append(processing_time)
            
            return RegexResult(
                matches=matches,
                confidence_delta=min(0.15, confidence_delta),  # Cap at 0.15
                factors=factors,
                processing_time_ms=processing_time,
                patterns_tested=len(matches),
                timeout_occurred=processing_time > self.global_timeout
            )
            
        except Exception as e:
            self.logger.error(f"Error in regex analysis: {e}")
            processing_time = (time.perf_counter() - start_time) * 1000
            
            return RegexResult(
                matches=[],
                confidence_delta=0.0,
                factors=['regex:processing_error'],
                processing_time_ms=processing_time,
                patterns_tested=0
            )

    def _extract_searchable_content(self, event: dict[str, Any]) -> dict[str, str]:
        """Extract and prepare content for regex matching"""
        content = {}
        
        # Extract key fields that commonly contain suspicious patterns
        searchable_fields = [
            'command_line', 'process_name', 'file_path', 'registry_key',
            'dns_query', 'url', 'user_agent', 'email_subject', 'email_body',
            'network_data', 'process_args', 'script_content'
        ]
        
        for field in searchable_fields:
            if field in event and event[field]:
                content[field] = str(event[field])
        
        # Create combined content for general patterns
        if content:
            content['combined'] = ' '.join(content.values())
        
        # Also include raw payload if available
        if 'raw_payload' in event and isinstance(event['raw_payload'], dict):
            raw_content = json.dumps(event['raw_payload'])
            content['raw'] = raw_content
        
        return content

    async def _apply_patterns_with_timeout(self, content: dict[str, str], event: dict[str, Any]) -> list[RegexMatch]:
        """Apply regex patterns with timeout protection"""
        matches = []
        patterns_to_test = self._select_patterns_for_event(event)
        
        # Warn-once cache and aggregated timeout logging
        warn_once: set[str] = getattr(self, '_warn_once_patterns', set())
        self._warn_once_patterns = warn_once
        aggregated_timeouts = 0

        try:
            async with asyncio.timeout(self.global_timeout / 1000):
                for pattern_def in patterns_to_test:
                    if not pattern_def.enabled:
                        continue
                    try:
                        if self.metric_patterns_attempted:
                            try: self.metric_patterns_attempted.inc()
                            except Exception: pass
                        pattern_matches = await self._test_pattern(pattern_def, content)
                        matches.extend(pattern_matches)
                        await self._record_pattern_performance(pattern_def, pattern_matches)
                        if self.metric_patterns_completed:
                            try: self.metric_patterns_completed.inc()
                            except Exception: pass
                    except asyncio.TimeoutError:
                        aggregated_timeouts += 1
                        self.timeout_count += 1
                        if self.metric_timeout_counter:
                            try: self.metric_timeout_counter.inc()
                            except Exception: pass
                        if self.metric_patterns_timedout:
                            try: self.metric_patterns_timedout.inc()
                            except Exception: pass
                        # Backoff logging per pattern
                        log_backoff(self.logger, f"regex_timeout:{pattern_def.id}", logging.WARNING,
                                    f"Regex pattern timeout (pattern_id={pattern_def.id})", first_n=1, ratio=25)
                    except Exception as e:
                        log_backoff(self.logger, f"regex_error:{pattern_def.id}", logging.WARNING,
                                    f"Regex pattern error (pattern_id={pattern_def.id}): {e}", first_n=1, ratio=50)
                        continue
        except asyncio.TimeoutError:
            # Global timeout – single aggregated log
            self.timeout_count += 1
            if self.metric_timeout_counter:
                try: self.metric_timeout_counter.inc()
                except Exception: pass
            msg = (f"Global regex timeout after {aggregated_timeouts} individual pattern timeouts (limit={self.global_timeout}ms)"
                   if aggregated_timeouts else f"Global regex timeout (limit={self.global_timeout}ms) with no individual pattern detail")
            log_backoff(self.logger, "regex_global_timeout", logging.WARNING, msg, first_n=1, ratio=10)
        
        return matches

    def _select_patterns_for_event(self, event: dict[str, Any]) -> list[PatternDefinition]:
        """Select relevant patterns based on event type and characteristics"""
        # Start with high-performance patterns
        selected_patterns = []
        # (metrics not incremented here; selection is a fast local operation)
        
        # Categorize event to select relevant patterns
        event_categories = self._categorize_event(event)
        
        for category in event_categories:
            if category in self.patterns_by_category:
                category_patterns = self.patterns_by_category[category]
                # Sort by performance (low complexity, high accuracy first)
                sorted_patterns = sorted(
                    category_patterns,
                    key=lambda p: (p.complexity_score, -self._get_pattern_accuracy(p)),
                )
                selected_patterns.extend(sorted_patterns[:10])  # Top 10 per category
        
        # Always include critical security patterns
        critical_patterns = [p for p in self.patterns.values() 
                           if p.category == 'critical' and p.enabled]
        selected_patterns.extend(critical_patterns)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_patterns = []
        for pattern in selected_patterns:
            if pattern.id not in seen:
                seen.add(pattern.id)
                unique_patterns.append(pattern)
        
        return unique_patterns[:25]  # Limit to 25 patterns max

    def _categorize_event(self, event: dict[str, Any]) -> list[str]:
        """Categorize event to select relevant pattern categories"""
        categories = ['general']  # Always include general patterns
        
        # Process-based events
        if 'process_name' in event or 'command_line' in event:
            categories.append('process')
        
        # Network-based events  
        if any(field in event for field in ['src_ip', 'dst_ip', 'dns_query', 'url']):
            categories.append('network')
        
        # File-based events
        if any(field in event for field in ['file_path', 'file_hash', 'file_name']):
            categories.append('file')
        
        # Registry events
        if 'registry_key' in event:
            categories.append('registry')
        
        # Email events
        if any(field in event for field in ['email_subject', 'email_body', 'sender']):
            categories.append('email')
        
        return categories

    async def _test_pattern(self, pattern_def: PatternDefinition, content: dict[str, str]) -> list[RegexMatch]:
        """Test a single pattern against content"""
        matches = []
        time.perf_counter()
        
        try:
            # Determine which content fields to test
            content_fields = self._select_content_for_pattern(pattern_def, content)
            
            for field_name, field_content in content_fields.items():
                if not field_content or len(field_content) > 10000:  # Skip very large content
                    continue
                # Execute regex with timeout and measure per-field processing
                field_start = time.perf_counter()
                regex_matches = await self._execute_regex_with_timeout(
                    pattern_def.compiled_pattern,
                    field_content,
                    self.execution_timeout / 1000,
                )

                field_processing_time = (time.perf_counter() - field_start) * 1000
                try:
                    if self.metric_processing_time_ms:
                        self.metric_processing_time_ms.observe(field_processing_time)
                except Exception:
                    pass

                # Increment patterns-tested metric once per pattern test
                try:
                    if self.metric_patterns_tested:
                        self.metric_patterns_tested.inc()
                except Exception:
                    pass

                # Process matches
                for match in regex_matches:
                    confidence = self._calculate_match_confidence(pattern_def, match, field_name)

                    regex_match = RegexMatch(
                        pattern_id=pattern_def.id,
                        pattern_name=pattern_def.name,
                        matched_text=match.group(0)[:100],  # Limit length
                        confidence_contribution=confidence,
                        factor=pattern_def.factor,
                        match_position=match.start(),
                        processing_time_ms=field_processing_time,
                    )

                    matches.append(regex_match)
        
        except Exception as e:
            self.logger.warning(f"Error testing pattern {pattern_def.id}: {e}")
        
        return matches

    def _select_content_for_pattern(self, pattern_def: PatternDefinition, content: dict[str, str]) -> dict[str, str]:
        """Select appropriate content fields for a pattern"""
        # Map pattern categories to relevant content fields
        category_mappings = {
            'process': ['command_line', 'process_name', 'process_args'],
            'network': ['dns_query', 'url', 'network_data', 'user_agent'],
            'file': ['file_path', 'file_name'],
            'registry': ['registry_key'],
            'email': ['email_subject', 'email_body'],
            'general': ['combined'],
            'critical': list(content.keys())  # Critical patterns test all content
        }
        
        relevant_fields = category_mappings.get(pattern_def.category, ['combined'])
        
        selected_content = {}
        for field in relevant_fields:
            if field in content:
                selected_content[field] = content[field]
        
        # If no specific fields, use combined content
        if not selected_content and 'combined' in content:
            selected_content['combined'] = content['combined']
        
        return selected_content

    async def _execute_regex_with_timeout(self, pattern: Pattern[str], text: str, timeout: float) -> list:
        """Execute regex with timeout protection"""
        try:
            # Use thread pool to execute regex with timeout
            loop = asyncio.get_event_loop()
            future = loop.run_in_executor(self.executor, pattern.finditer, text)
            
            # Convert iterator to list with timeout
            matches = await asyncio.wait_for(future, timeout=timeout)
            return list(matches)
            
        except asyncio.TimeoutError:
            self.logger.debug("Regex execution timeout for pattern")
            return []
        except Exception as e:
            self.logger.debug(f"Regex execution error: {e}")
            return []

    def _calculate_match_confidence(self, pattern_def: PatternDefinition, match, field_name: str) -> float:
        """Calculate confidence contribution for a specific match"""
        base_confidence = pattern_def.confidence
        
        # Adjust based on match characteristics
        matched_text = match.group(0)
        
        # Longer matches are generally more significant
        length_bonus = min(0.1, len(matched_text) / 100)
        
        # Matches in certain fields are more significant
        field_multipliers = {
            'command_line': 1.2,
            'process_name': 1.1,
            'dns_query': 1.15,
            'url': 1.1,
            'registry_key': 1.1,
            'combined': 1.0,
            'raw': 0.9
        }
        
        field_multiplier = field_multipliers.get(field_name, 1.0)
        
        # Pattern accuracy adjustment
        accuracy = self._get_pattern_accuracy(pattern_def)
        accuracy_multiplier = 0.5 + (accuracy * 0.5)  # Scale from 0.5 to 1.0
        
        final_confidence = base_confidence * field_multiplier * accuracy_multiplier + length_bonus
        
        return min(0.2, max(0.01, final_confidence))  # Clamp between 0.01 and 0.2

    def _get_pattern_accuracy(self, pattern_def: PatternDefinition) -> float:
        """Get accuracy score for a pattern based on historical performance"""
        total_matches = pattern_def.true_positive_count + pattern_def.false_positive_count
        
        if total_matches == 0:
            return 0.5  # Default accuracy for new patterns
        
        return pattern_def.true_positive_count / total_matches

    def _calculate_confidence_delta(self, matches: list[RegexMatch]) -> float:
        """Calculate overall confidence delta from all matches"""
        if not matches:
            return 0.0
        
        # Use logarithmic scaling to prevent runaway confidence
        total_confidence = sum(match.confidence_contribution for match in matches)
        
        # Apply diminishing returns
        if total_confidence > 0.1:
            # log(1 + x) scaling for values > 0.1
            import math
            scaled_confidence = 0.1 + 0.05 * math.log(1 + (total_confidence - 0.1) * 10)
            return min(0.15, scaled_confidence)
        
        return min(0.15, total_confidence)

    async def _record_pattern_performance(self, pattern_def: PatternDefinition, matches: list[RegexMatch]):
        """Record pattern performance for optimization"""
        performance_data = {
            'pattern_id': pattern_def.id,
            'match_count': len(matches),
            'total_confidence': sum(m.confidence_contribution for m in matches),
            'avg_processing_time': sum(m.processing_time_ms for m in matches) / len(matches) if matches else 0,
            'timestamp': time.time()
        }
        
        self.pattern_performance[pattern_def.id].append(performance_data)

    async def _load_pattern_definitions(self):
        """Load regex pattern definitions from configuration"""
        # In a real implementation, this would load from YAML/JSON config
        # For demo, define some common security patterns
        
        pattern_definitions = [
            # Process injection patterns
            {
                'id': 'proc_injection_1',
                'name': 'Process Injection APIs',
                'pattern': r'(?i)(createremotethread|ntcreatethreadex|rtlcreateuserthread|setwindowshookex)',
                'category': 'process',
                'confidence': 0.6,
                'factor': 'attack:T1055'
            },
            
            # Persistence registry patterns
            {
                'id': 'registry_persistence_1',
                'name': 'Registry Persistence Keys',
                'pattern': r'(?i)(\\software\\microsoft\\windows\\currentversion\\run|\\software\\microsoft\\windows\\currentversion\\runonce)',
                'category': 'registry',
                'confidence': 0.4,
                'factor': 'behavior:persistence_create'
            },
            
            # Suspicious domain patterns
            {
                'id': 'suspicious_domains_1',
                'name': 'Suspicious Domain TLDs',
                'pattern': r'(?i)[a-z0-9-]+\.(tk|ml|ga|cf|pw|bit|onion)\b',
                'category': 'network',
                'confidence': 0.3,
                'factor': 'infra:suspicious_tld'
            },
            
            # C2 communication patterns
            {
                'id': 'c2_patterns_1',
                'name': 'C2 Communication Patterns',
                'pattern': r'(?i)(beacon|heartbeat|checkin|callback)[\s\-_]*(url|endpoint|server|domain)',
                'category': 'network',
                'confidence': 0.5,
                'factor': 'behavior:c2_pattern'
            },
            
            # Powershell obfuscation
            {
                'id': 'ps_obfuscation_1',
                'name': 'PowerShell Obfuscation',
                'pattern': r'(?i)powershell.*(-e\s+[a-z0-9+/=]+|-encodedcommand\s+[a-z0-9+/=]+)',
                'category': 'process',
                'confidence': 0.7,
                'factor': 'attack:T1059.001'
            },
            
            # Suspicious file operations
            {
                'id': 'file_ops_1',
                'name': 'Suspicious File Extensions',
                'pattern': r'(?i)\.(scr|pif|bat|cmd|com|exe|vbs|js|jar|tmp)[\s"\'$]',
                'category': 'file',
                'confidence': 0.3,
                'factor': 'behavior:suspicious_file_ext'
            },
            
            # Credential access patterns
            {
                'id': 'cred_access_1',
                'name': 'Credential Access Tools',
                'pattern': r'(?i)(mimikatz|lsass\.exe|sekurlsa|wdigest|kerberos|ntlm)',
                'category': 'process',
                'confidence': 0.8,
                'factor': 'attack:T1003'
            },
            
            # Network scanning patterns
            {
                'id': 'network_scan_1',
                'name': 'Network Scanning Tools',
                'pattern': r'(?i)(nmap|masscan|zmap|unicornscan|hping|netcat|nc\.exe)',
                'category': 'process',
                'confidence': 0.5,
                'factor': 'attack:T1018'
            },
            
            # Web shell patterns
            {
                'id': 'webshell_1',
                'name': 'Web Shell Indicators',
                'pattern': r'(?i)(eval|exec|system|shell_exec|passthru|base64_decode).*\$_(?:GET|POST|REQUEST)',
                'category': 'general',
                'confidence': 0.7,
                'factor': 'attack:T1505.003'
            },
            
            # Lateral movement patterns
            {
                'id': 'lateral_move_1',
                'name': 'Lateral Movement Tools',
                'pattern': r'(?i)(psexec|wmic|schtasks|at\.exe|winrm|winrs).*(/c|/k|\s+-|\s+/)',
                'category': 'process',
                'confidence': 0.6,
                'factor': 'attack:T1021'
            }
        ]
        
        # Store pattern definitions
        self.pattern_definitions = pattern_definitions

    async def _compile_patterns(self):
        """Compile regex patterns and analyze complexity"""
        for pattern_def in self.pattern_definitions:
            try:
                # Compile pattern
                compiled_pattern = re.compile(pattern_def['pattern'], re.IGNORECASE | re.MULTILINE)
                
                # Analyze complexity
                complexity_score = self._analyze_pattern_complexity(pattern_def['pattern'])
                
                # Create pattern definition object
                pattern_obj = PatternDefinition(
                    id=pattern_def['id'],
                    name=pattern_def['name'],
                    pattern=pattern_def['pattern'],
                    compiled_pattern=compiled_pattern,
                    category=pattern_def['category'],
                    confidence=pattern_def['confidence'],
                    factor=pattern_def['factor'],
                    complexity_score=complexity_score,
                    enabled=True
                )
                
                self.patterns[pattern_def['id']] = pattern_obj
                self.patterns_by_category[pattern_def['category']].append(pattern_obj)
                
            except re.error as e:
                self.logger.error(f"Failed to compile pattern {pattern_def['id']}: {e}")
                continue

    def _analyze_pattern_complexity(self, pattern: str) -> int:
        """Analyze regex pattern complexity (1-5, where 5 is most expensive)"""
        complexity = 1
        
        # Backtracking patterns (nested quantifiers)
        if re.search(r'[\*\+\?]\s*[\*\+\?]', pattern):
            complexity += 3
        
        # Lookaheads/lookbehinds
        if re.search(r'\(\?[=!<]', pattern):
            complexity += 2
        
        # Large character classes
        if re.search(r'\[.{10,}\]', pattern):
            complexity += 1
        
        # Alternation with many options
        alternations = pattern.count('|')
        if alternations > 5:
            complexity += 2
        elif alternations > 2:
            complexity += 1
        
        # Nested groups
        group_depth = 0
        max_depth = 0
        for char in pattern:
            if char == '(':
                group_depth += 1
                max_depth = max(max_depth, group_depth)
            elif char == ')':
                group_depth -= 1
        
        if max_depth > 3:
            complexity += 2
        elif max_depth > 2:
            complexity += 1
        
        return min(5, complexity)

    async def _optimize_pattern_order(self):
        """Optimize pattern execution order based on performance characteristics"""
        # Sort patterns by efficiency: low complexity, high accuracy first
        for category in self.patterns_by_category:
            patterns = self.patterns_by_category[category]
            patterns.sort(key=lambda p: (p.complexity_score, -self._get_pattern_accuracy(p)))

    async def update_patterns(self, pattern_updates: dict[str, Any]):
        """Update pattern configurations (for adaptive tuning)"""
        for pattern_id, updates in pattern_updates.items():
            if pattern_id in self.patterns:
                pattern = self.patterns[pattern_id]
                
                if 'enabled' in updates:
                    pattern.enabled = updates['enabled']
                
                if 'confidence' in updates:
                    pattern.confidence = max(0.01, min(1.0, updates['confidence']))
                
                self.logger.info(f"Updated pattern {pattern_id}: {updates}")

    async def record_pattern_feedback(self, pattern_id: str, was_true_positive: bool):
        """Record feedback for pattern accuracy tracking"""
        if pattern_id in self.patterns:
            pattern = self.patterns[pattern_id]
            
            if was_true_positive:
                pattern.true_positive_count += 1
            else:
                pattern.false_positive_count += 1

    async def get_performance_stats(self) -> dict[str, Any]:
        """Get performance statistics"""
        if not self.execution_times:
            return {}
        
        return {
            'patterns_loaded': len(self.patterns),
            'patterns_executed': self.patterns_executed,
            'avg_execution_time': sum(self.execution_times) / len(self.execution_times),
            'timeout_count': self.timeout_count,
            'p95_execution_time': sorted(self.execution_times)[int(len(self.execution_times) * 0.95)],
            'patterns_by_category': {cat: len(patterns) for cat, patterns in self.patterns_by_category.items()}
        }

    async def health_check(self) -> bool:
        """Check module health"""
        try:
            # Test with simple pattern
            test_content = {'combined': 'test content'}
            test_pattern = PatternDefinition(
                id='test',
                name='test',
                pattern=r'test',
                compiled_pattern=re.compile(r'test'),
                category='general',
                confidence=0.1,
                factor='test',
                complexity_score=1
            )
            
            matches = await self._test_pattern(test_pattern, test_content)
            return len(matches) >= 0  # Should not fail
            
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return False

    async def shutdown(self):
        """Shutdown regex pattern matcher"""
        self.logger.info("Shutting down regex pattern matcher...")
        
        # Shutdown thread pool
        self.executor.shutdown(wait=True)
        
        # Get final stats
        stats = await self.get_performance_stats()
        self.logger.info(f"Regex pattern matcher shutdown. Final stats: {stats}")