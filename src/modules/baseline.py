"""
Baseline Module - Deterministic pattern matching and threat intelligence lookups
Author: Security Engineering Team
Version: 1.0.0

Provides fast, deterministic filtering using hash tables, bloom filters, and known indicators.
Serves as failsafe that works even when all AI systems are down.
Target: <1ms p95 processing time.
"""

import asyncio
import os
import hashlib
import ipaddress
import json
import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple
try:
    from modules.threat_intel_cache import get_threat_intel_cache
except Exception:  # pragma: no cover
    get_threat_intel_cache = None  # type: ignore

# Efficient data structures (with graceful fallbacks if optional deps missing)
try:
    from pybloom_live import BloomFilter  # type: ignore
except ImportError:  # pragma: no cover - fallback path
    class BloomFilter:  # Minimal stand‑in so the module still functions
        """Very small in‑memory fallback when pybloom_live isn't installed.
        NOTE: This behaves like a plain set (no probabilistic compression).
        Suitable for dev only – install pybloom-live for memory efficiency & speed:
            pip install pybloom-live
        """
        def __init__(self, capacity: int = 100000, error_rate: float = 0.001):  # noqa: D401
            self._data = set()
        def add(self, item):
            self._data.add(item)
        def __contains__(self, item):
            return item in self._data

try:
    import mmh3  # type: ignore  # Fast hashing if available
    def fast_hash(val: str) -> int:
        return mmh3.hash(val)
except ImportError:  # pragma: no cover
    def fast_hash(val: str) -> int:
        # Fallback – less uniform but acceptable for development use
        return hash(val) & 0xffffffff


@dataclass
class BaselineResult:
    """Result from baseline pattern matching"""
    confidence: float
    factors: list[str]
    terminal: bool  # True if this result is definitive
    disposition: str | None = None
    processing_time: float = 0.0
    matched_indicators: list[dict[str, Any]] = None


@dataclass
class ThreatIndicator:
    """A threat intelligence indicator"""
    value: str
    type: str  # 'ip', 'domain', 'hash', 'url'
    confidence: float
    source: str
    last_seen: float
    tags: list[str]


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
        self.known_bad_ips: set[str] = set()
        self.known_bad_domains: set[str] = set()
        self.known_bad_hashes: set[str] = set()
        self.known_good_patterns: set[str] = set()
        
        # Pattern frequency tracking for learning
        self.pattern_frequencies = defaultdict(int)
        self.false_positive_patterns = defaultdict(int)
        
        # Performance metrics
        self.lookups_performed = 0
        self.cache_hits = 0
        self.processing_times = []
        
        # Pre-compiled regex for common patterns (compile once)
        self.ip_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.domain_regex = re.compile(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
        # Suspicious TLDs constant cached
        self.suspicious_tlds = ('.tk','.ml','.ga','.cf','.pw')
        self.hash_regex = {
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b')
        }

    async def initialize(self):
        """Initialize baseline module with threat intelligence data"""
        self.logger.info("Initializing baseline module...")
        # Allow tests to skip heavy warm initialization (loads & seeding)
        skip_warm = os.getenv('BASELINE_SKIP_WARM', '0').lower() in ('1', 'true', 'yes')
        if skip_warm:
            self.logger.info("BASELINE_SKIP_WARM set; skipping warm indicator loads")
            return
        
        # Load persisted suppression state (known_good_patterns + false_positive_patterns)
        suppression_path = os.getenv('BASELINE_SUPPRESSION_PATH', '')
        if suppression_path:
            try:
                import json as _json
                with open(suppression_path, 'r', encoding='utf-8') as _f:
                    _state = _json.load(_f)
                for _p in _state.get('known_good_patterns', []):
                    self.known_good_patterns.add(_p)
                    self.benign_patterns.add(_p)
                for _k, _v in _state.get('false_positive_patterns', {}).items():
                    self.false_positive_patterns[_k] = _v
                self.logger.info('Loaded suppression state from %s', suppression_path)
            except Exception as _e:
                self.logger.warning('Could not load suppression state from %s: %s', suppression_path, _e)

        # Load threat intelligence indicators
        await self._load_threat_indicators()
        
        # Load benign patterns from historical data
        await self._load_benign_patterns()
        
        self.logger.info(f"Baseline module initialized. "
                        f"Loaded {len(self.known_bad_ips)} known bad IPs, "
                        f"{len(self.known_bad_domains)} known bad domains, "
                        f"{len(self.known_bad_hashes)} known bad hashes")

    async def check(self, event: dict[str, Any]) -> BaselineResult:
        """
        Main baseline check - fast deterministic analysis.
        Returns confidence score and factors within <1ms target.
        """
        start_time = time.perf_counter()
        # Adaptive time budget (ms) for fast path; default 4ms to keep headroom under 5ms test threshold.
        try:
            _budget_ms = float(os.getenv('BASELINE_CHECK_TIME_BUDGET_MS', '4'))
        except Exception:
            _budget_ms = 4.0
        time_budget_sec = _budget_ms / 1000.0
        _time_exceeded = False
        self.lookups_performed += 1
        
        try:
            factors = []
            confidence = 0.0
            matched_indicators = []
            
            # Extract indicators from event
            indicators = self._extract_indicators(event)
            # Fast path: if no indicators present, skip heavy logic
            if not any(indicators.values()):
                processing_time = (time.perf_counter() - start_time) * 1000
                return BaselineResult(confidence=0.0, factors=[], terminal=False, processing_time=processing_time, matched_indicators=[])
            # Decide whether to enable deadline checks (only necessary for large indicator sets)
            total_indicators = sum(len(v) for v in indicators.values())
            deadline = None
            if total_indicators > 10:
                deadline = start_time + time_budget_sec

            # Check against known bad indicators (inline check for hot path)
            event_type = (event.get('event_type') or '').lower()
            ti_enabled = event_type in ('network', 'dns', 'http', 'flow', 'alert', 'file')
            ti_cache = get_threat_intel_cache if ti_enabled else None

            # Cache frequently used attributes to local variables for speed
            known_bad_ips = self.known_bad_ips
            malicious_ips = self.malicious_ips
            known_bad_domains = self.known_bad_domains
            malicious_domains = self.malicious_domains
            known_bad_hashes = self.known_bad_hashes
            malicious_hashes = self.malicious_hashes
            suspicious_tlds = self.suspicious_tlds

            # Use a set to collect factors (de-dup) and minimize list ops
            factor_set: Set[str] = set()

            for indicator_type, values in indicators.items():
                if deadline is not None:
                    # Check deadline once per indicator_type when enabled
                    if time.perf_counter() > deadline:
                        _time_exceeded = True
                        break

                for value in values:
                    # Threat intel cache lookup only if relevant event type
                    if ti_cache:
                        try:
                            cache_obj = ti_cache()
                            if cache_obj and cache_obj.match_ioc(value):
                                matched_indicators.append({'type': indicator_type, 'value': value, 'confidence': 0.85, 'source': 'threat_intel_cache'})
                                factor_set.add('baseline:intel_match')
                                confidence = max(confidence, 0.85)
                                continue
                        except Exception:
                            pass

                    # Inline the indicator checks to avoid async/function call overhead
                    found_confidence = 0.0
                    if indicator_type == 'ips':
                        if value in known_bad_ips:
                            found_confidence = 0.9
                            factor_set.add('baseline:known_bad_ip')
                        elif value in malicious_ips:
                            found_confidence = 0.7
                            factor_set.add('baseline:suspicious_ip')

                    elif indicator_type == 'domains':
                        if value in known_bad_domains:
                            found_confidence = 0.9
                            factor_set.add('baseline:known_bad_domain')
                        elif value in malicious_domains:
                            found_confidence = 0.7
                            factor_set.add('baseline:suspicious_domain')
                        # Suspicious TLDs
                        for tld in suspicious_tlds:
                            if value.endswith(tld):
                                found_confidence = max(found_confidence, 0.3)
                                factor_set.add('baseline:suspicious_tld')
                                break

                    elif indicator_type == 'hashes':
                        if value in known_bad_hashes:
                            found_confidence = 0.95
                            factor_set.add('baseline:known_malware_hash')
                        elif value in malicious_hashes:
                            found_confidence = 0.8
                            factor_set.add('baseline:suspicious_hash')

                    if found_confidence > 0.0:
                        confidence = max(confidence, found_confidence)
                        matched_indicators.append({
                            'type': indicator_type,
                            'value': value,
                            'confidence': found_confidence
                        })
                if _time_exceeded:
                    break

            # Convert factor_set back to list for result
            factors = list(factor_set)
            
            # Check for known benign patterns
            if not _time_exceeded:
                # Quick heuristic: only check benign patterns if confidence already elevated
                if confidence > 0.0:
                    benign_confidence = await self._check_benign_patterns(event)
                    if benign_confidence > 0:
                        factors.append('baseline:known_benign')
                        confidence = max(0, confidence - benign_confidence)
            if _time_exceeded:
                processing_time = (time.perf_counter() - start_time) * 1000
                return BaselineResult(
                    confidence=confidence,
                    factors=factors + ['baseline:time_budget_exceeded'],
                    terminal=False,
                    disposition=None,
                    processing_time=processing_time,
                    matched_indicators=matched_indicators
                )
            
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
            
            # Metrics: track baseline intel hit-rate (import lazily to avoid circulars)
            try:
                from metrics.baseline_intel_metrics import observe as _baseline_observe, init as _baseline_init  # type: ignore
                _baseline_init()
                _baseline_observe(any(f == 'baseline:intel_match' for f in factors))
            except Exception:
                pass

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

    def _extract_indicators(self, event: dict[str, Any]) -> dict[str, list[str]]:
        """Extract IOCs from event data"""
        indicators = {
            'ips': [],
            'domains': [],
            'hashes': [],
            'urls': []
        }
        # Heuristic: if common indicator fields absent and command line short, skip expensive scan
        fast_fields = ('src_ip','dst_ip','domain','file_hash','process_hash')
        if not any(f in event for f in fast_fields):
            cmd = str(event.get('command_line') or event.get('cmdline') or '')
            if len(cmd) < 32:
                return indicators
        
        # Direct field harvesting first (fast path) — avoids JSON dump if enough explicit fields present
        for field in fast_fields:
            val = event.get(field)
            if not val:
                continue
            sval = str(val).lower()
            if field.endswith('_ip'):
                try:
                    ip = ipaddress.ip_address(sval)
                    if not ip.is_private and not ip.is_loopback:
                        indicators['ips'].append(sval)
                except Exception:
                    pass
            elif field == 'domain':
                indicators['domains'].append(sval)
            elif 'hash' in field:
                indicators['hashes'].append(sval)
        
        # Decide if deep scan required (network or file events likely to embed extra IOCs)
        deep_scan = (event.get('event_type') or '').lower() in ('network', 'dns', 'http', 'flow', 'file', 'alert')
        # For non-deep events (e.g., process_start) we avoid expensive JSON serialization and regex scans.
        if not deep_scan:
            for key in indicators:
                indicators[key] = list(set(indicators[key]))
            return indicators
        
        try:
            text_content = json.dumps(event, separators=(',',':')).lower()
        except Exception:
            text_content = str(event).lower()
        
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
        for _hash_type, regex in self.hash_regex.items():
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

    async def _check_indicator(self, indicator_type: str, value: str) -> dict[str, Any] | None:
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
            # Suspicious TLDs
            if any(value.endswith(tld) for tld in self.suspicious_tlds):
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

    async def _check_benign_patterns(self, event: dict[str, Any]) -> float:
        """Check for known benign patterns"""
        benign_confidence = 0.0

        # Check specific fields for benign indicators
        if 'process_name' in event:
            process_name = str(event['process_name']).lower()

            # Microsoft Windows Security Components (HIGH CONFIDENCE)
            microsoft_security_processes = {
                'mpam-d.exe',           # Windows Defender antimalware
                'mpam-fe_bd.exe',       # Windows Defender signatures
                'msmpeng.exe',          # Windows Defender Antimalware Service
                'mssense.exe',          # Windows Defender Advanced Threat Protection
                'windefend.exe',        # Windows Defender Service
                'mpcmdrun.exe',         # Windows Defender Command Line Utility
                'nissrv.exe',           # Windows Defender Network Inspection Service
                'trustedinstaller.exe', # Windows Trusted Installer
                'svchost.exe',          # Windows Service Host
                'wuauclt.exe',          # Windows Update Auto Update Client
                'wudfhost.exe',         # Windows User-mode Driver Framework Host
                'dwm.exe',              # Desktop Window Manager
                'csrss.exe',            # Client Server Runtime Process
                'lsass.exe',            # Local Security Authority Subsystem Service
                'winlogon.exe',         # Windows Logon Process
                'smss.exe',             # Session Manager Subsystem
                'services.exe',         # Services Control Manager
                'system'                # System process
            }

            if process_name in microsoft_security_processes:
                benign_confidence = max(benign_confidence, 0.8)  # High confidence for MS security

            # Windows Built-in Tools and Utilities
            windows_builtin_tools = {
                'snippingtool.exe',     # Snipping Tool
                'calc.exe',             # Calculator
                'notepad.exe',          # Notepad
                'mspaint.exe',          # MS Paint
                'wordpad.exe',          # WordPad
                'charmap.exe',          # Character Map
                'cleanmgr.exe',         # Disk Cleanup
                'defrag.exe',           # Disk Defragmenter
                'dxdiag.exe',           # DirectX Diagnostic Tool
                'msconfig.exe',         # System Configuration
                'msinfo32.exe',         # System Information
                'regedit.exe',          # Registry Editor
                'taskmgr.exe',          # Task Manager
                'control.exe',          # Control Panel
                'explorer.exe'          # Windows Explorer
            }

            if process_name in windows_builtin_tools:
                benign_confidence = max(benign_confidence, 0.6)  # Good confidence for built-in tools

            # Common legitimate applications
            common_legitimate_processes = {
                'chrome.exe', 'firefox.exe', 'edge.exe', 'iexplore.exe',
                'winword.exe', 'excel.exe', 'outlook.exe', 'powerpnt.exe',
                'teams.exe', 'skype.exe', 'zoom.exe',
                'adobe.exe', 'acrobat.exe', 'photoshop.exe',
                'steam.exe', 'discord.exe', 'spotify.exe'
            }

            if process_name in common_legitimate_processes:
                benign_confidence = max(benign_confidence, 0.4)  # Moderate confidence

        # Check file path patterns for legitimate software locations
        if 'process_path' in event or 'path' in event:
            file_path = str(event.get('process_path', event.get('path', ''))).lower()

            # Microsoft/Windows system directories (HIGH TRUST)
            microsoft_paths = [
                'c:\\windows\\system32\\',
                'c:\\windows\\syswow64\\',
                'c:\\windows\\systemtemp\\',
                'c:\\windows\\temp\\',
                'c:\\windows\\softwaredistribution\\',
                'c:\\program files\\windows defender\\',
                'c:\\program files (x86)\\windows defender\\',
                'c:\\programdata\\microsoft\\windows defender\\'
            ]

            if any(file_path.startswith(path) for path in microsoft_paths):
                benign_confidence = max(benign_confidence, 0.7)  # High confidence for MS paths

            # Known legitimate software vendors
            trusted_vendor_paths = [
                'c:\\program files\\microsoft',
                'c:\\program files (x86)\\microsoft',
                'c:\\program files\\google\\',
                'c:\\program files (x86)\\google\\',
                'c:\\program files\\mozilla\\',
                'c:\\program files (x86)\\mozilla\\',
                'c:\\program files\\adobe\\',
                'c:\\program files (x86)\\adobe\\',
                'c:\\program files\\teamviewer\\',
                'c:\\program files (x86)\\teamviewer\\',
                'c:\\program files\\epson\\',
                'c:\\program files (x86)\\epson\\'
            ]

            if any(file_path.startswith(path) for path in trusted_vendor_paths):
                benign_confidence = max(benign_confidence, 0.5)  # Good confidence for trusted vendors

        # Check digital signature information if available
        if 'signed' in event and event['signed']:
            if 'signer' in event:
                signer = str(event['signer']).lower()
                trusted_signers = {
                    'microsoft corporation',
                    'microsoft windows',
                    'google llc',
                    'mozilla corporation',
                    'adobe systems incorporated',
                    'teamviewer gmbh',
                    'epson corporation'
                }

                if any(trusted in signer for trusted in trusted_signers):
                    benign_confidence = max(benign_confidence, 0.6)  # Good confidence for trusted signers

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

    def _apply_heuristics(self, event: dict[str, Any], confidence: float, factors: list[str]) -> float:
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

    def _create_event_signature(self, event: dict[str, Any]) -> str:
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

    async def learn_benign(self, event: dict[str, Any]):
        """Learn from confirmed benign events"""
        signature = self._create_event_signature(event)
        self.known_good_patterns.add(signature)
        
        # Add to bloom filter for fast lookup
        self.benign_patterns.add(signature)

    async def learn_false_positive(self, event: dict[str, Any]):
        """Learn from false positive events"""
        signature = self._create_event_signature(event)
        self.false_positive_patterns[signature] += 1

        # Also create an identity-based signature when actor + action are present
        actor = event.get('actor') or event.get('user') or event.get('identity')
        action = event.get('action')
        if actor and action:
            identity_sig = f"identity:{actor}:{action}"
            self.false_positive_patterns[identity_sig] += 1

        # Persist updated suppression state to disk
        suppression_path = os.getenv('BASELINE_SUPPRESSION_PATH', '')
        if suppression_path:
            try:
                import json as _json
                _state = {
                    'known_good_patterns': list(self.known_good_patterns),
                    'false_positive_patterns': dict(self.false_positive_patterns),
                }
                with open(suppression_path, 'w', encoding='utf-8') as _f:
                    _json.dump(_state, _f)
            except Exception as _e:
                self.logger.warning('Could not persist suppression state to %s: %s', suppression_path, _e)

    async def quick_check(self, event: dict[str, Any]) -> BaselineResult:
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
        # Prefer integrated ThreatIntelClient when available; fall back to demo samples
        seeded = False
        try:
            from integrations.threat_intel_client import CLIENT as _TI  # type: ignore
            ti = _TI
            # Seed from current intel client caches (respect that TTL purge runs in client)
            added = 0
            for ip in getattr(ti, 'ip_set', set()):
                self.known_bad_ips.add(ip); self.malicious_ips.add(ip); added += 1
            for d in getattr(ti, 'domain_set', set()):
                self.known_bad_domains.add(d); self.malicious_domains.add(d); added += 1
            for h in getattr(ti, 'hash_set', set()):
                self.known_bad_hashes.add(h); self.malicious_hashes.add(h); added += 1
            # Only treat as seeded if we actually added indicators
            if added > 0:
                seeded = True
        except Exception:
            seeded = False
        if seeded:
            return
        # Fallback demo indicators
        sample_bad_ips = ['185.220.101.1', '185.220.102.1', '192.42.116.1']
        sample_bad_domains = ['malware-example.com', 'phishing-site.tk', 'bad-domain.ml']
        sample_bad_hashes = [
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'd41d8cd98f00b204e9800998ecf8427e'
        ]
        for ip in sample_bad_ips:
            self.known_bad_ips.add(ip); self.malicious_ips.add(ip)
        for domain in sample_bad_domains:
            self.known_bad_domains.add(domain); self.malicious_domains.add(domain)
        for hash_val in sample_bad_hashes:
            self.known_bad_hashes.add(hash_val); self.malicious_hashes.add(hash_val)

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

    async def get_performance_stats(self) -> dict[str, Any]:
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