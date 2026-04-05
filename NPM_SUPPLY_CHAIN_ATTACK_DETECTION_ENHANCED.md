# NPM & Supply Chain Attack Detection: Enhanced Implementation Guide
## JanuSec Platform Integration

**Version:** 2.0 (Enhanced)
**Date:** 2025-11-30
**Status:** Production-Ready RFC
**Scope:** NPM, PyPI, GitHub Actions, CI/CD Supply Chain Attacks

---

## Executive Summary

This document enhances the previous ChatGPT analysis with:
1. **Verified threat intelligence** from 2024-2025 supply chain attacks
2. **Detailed JanuSec 21-step pipeline integration**
3. **HopGraph supply chain node/edge schema**
4. **Binary analysis integration for package payloads**
5. **Tier 1/Tier 2 LLM prompt engineering**
6. **Missing detection capabilities** identified

### Key 2025 Supply Chain Attacks (Verified)

| Attack | Date | Scale | Vector | Detection Gap |
|--------|------|-------|--------|---------------|
| **Shai-Hulud 1.0** | Sept 15, 2025 | 500+ packages | npm postinstall worm | Self-propagating credential theft |
| **Shai-Hulud 2.0** | Nov 2025 | 25,000+ repos | npm preinstall + wiper | Destructive fallback mechanism |
| **npm Debug/Chalk** | Sept 8, 2025 | 18 packages, 2.6B downloads | Phishing → crypto wallet hijack | Browser-only payload |
| **tj-actions/changed-files** | March 14, 2025 | 23,000+ repos | GitHub Actions tag manipulation | CI/CD memory dump |
| **reviewdog/action-setup** | March 11, 2025 | Cascading to tj-actions | Tag redirection | Contributor compromise |
| **XZ Utils** | March 2024 | Linux ecosystem | 2-year maintainer compromise | SSH backdoor (CVSS 10) |

---

## Part 1: What the Previous Document Got Right

### ✅ Accurate Coverage

1. **Shai-Hulud Attack Mechanism** - Correctly identified:
   - Self-replicating worm behavior via npm lifecycle scripts
   - Credential harvesting (.npmrc, .git-credentials, cloud tokens)
   - GitHub API exfiltration to public repos named "Shai-Hulud"
   - Multi-wave evolution (postinstall → preinstall)

2. **GitHub Actions Supply Chain** - Correctly identified:
   - tj-actions/changed-files compromise (CVE-2025-30066)
   - reviewdog cascading attack
   - Tag manipulation as attack vector
   - Memory dump exfiltration via workflow logs

3. **XZ Utils Backdoor** - Correctly identified:
   - Long-term social engineering (2+ years)
   - SSH authentication bypass
   - CVSS 10 severity
   - Nation-state attribution possibility

### ⚠️ What Needs Correction/Enhancement

| Previous Claim | Correction |
|----------------|------------|
| "Wave 1 September 2025" | First Shai-Hulud was September 15, 2025 (not early Sept) |
| "180+ packages Wave 1" | 500+ packages confirmed by CISA |
| "640 packages total" | Over 25,000 repositories affected in Wave 2 |
| "AI-generated with emojis" | Confirmed by Unit 42 - LLM-generated bash scripts |
| Detection "strong coverage" | **Gap**: Pre-execution scanning missing |

---

## Part 2: What Was Missing (Critical Gaps)

### 2.1 Missing Attack Vectors

```
PREVIOUSLY UNDOCUMENTED:
├── Dead Man's Switch (Shai-Hulud 2.0)
│   └── Wiper destroys ~/home if exfiltration fails
├── GitHub Logs as Exfiltration Channel
│   └── tj-actions used workflow logs, not external C2
├── Bun Runtime Obfuscation
│   └── Shai-Hulud 2.0 uses setup_bun.js, bun_environment.js
├── Double-Encoded Base64
│   └── tj-actions secrets were double-encoded in logs
└── Multi-Ecosystem Campaigns
    └── MUT-8694: Same actor targeting npm AND PyPI simultaneously
```

### 2.2 Missing Detection Capabilities

```python
# CRITICAL GAPS IN PREVIOUS ANALYSIS

DETECTION_GAPS = {
    'pre_execution_scanning': {
        'description': 'Static analysis BEFORE npm install',
        'impact': 'Cannot detect malicious postinstall until executed',
        'solution': 'GuardDog/Semgrep integration, lockfile scanning'
    },
    
    'ci_cd_runtime_monitoring': {
        'description': 'GitHub Actions workflow monitoring',
        'impact': 'Cannot detect tag manipulation or memory dumps',
        'solution': 'GitHub audit log ingestion, workflow behavior analysis'
    },
    
    'package_provenance_verification': {
        'description': 'SLSA attestation verification',
        'impact': 'Cannot verify package was built from claimed source',
        'solution': 'Sigstore/in-toto integration'
    },
    
    'dead_mans_switch_detection': {
        'description': 'Detect wiper fallback mechanisms',
        'impact': 'Cannot prevent data destruction if C2 blocked',
        'solution': 'Behavioral analysis for rm -rf patterns with network dependency'
    },
    
    'browser_payload_detection': {
        'description': 'Detect browser-only crypto wallet hijacking',
        'impact': 'npm debug attack was browser-only, server-side blind',
        'solution': 'Client-side JavaScript analysis, wallet API hooking detection'
    },
}
```

### 2.3 Missing YARA Rules

```yara
/*
 * MISSING: Shai-Hulud Detection Rules
 * These were not in the previous document
 */

rule Shai_Hulud_Worm_Indicator {
    meta:
        description = "Detects Shai-Hulud npm worm indicators"
        author = "JanuSec Research"
        date = "2025-11-30"
        reference = "https://unit42.paloaltonetworks.com/npm-supply-chain-attack/"
        
    strings:
        // Repository naming
        $repo_name1 = "Shai-Hulud" nocase
        $repo_name2 = "Sha1-Hulud" nocase
        $repo_desc = "The Second Coming" nocase
        
        // Credential file access
        $cred1 = ".npmrc"
        $cred2 = ".git-credentials"
        $cred3 = ".aws/credentials"
        
        // GitHub API exfiltration
        $api1 = "api.github.com/user/repos"
        $api2 = "api.github.com/repos"
        
        // npm token patterns
        $npm_token = /npm_[a-zA-Z0-9]{36}/
        
        // Shai-Hulud 2.0 specific
        $bun1 = "setup_bun.js"
        $bun2 = "bun_environment.js"
        
        // Wiper behavior
        $wiper1 = "rm -rf ~"
        $wiper2 = "rm -rf $HOME"
        $wiper3 = "rmdir /s /q %USERPROFILE%"
        
    condition:
        (any of ($repo_*)) or
        (2 of ($cred*) and any of ($api*)) or
        (any of ($bun*)) or
        (any of ($wiper*) and any of ($api*))
}

rule GitHub_Actions_Memory_Dump {
    meta:
        description = "Detects GitHub Actions memory dump attack (tj-actions style)"
        date = "2025-11-30"
        cve = "CVE-2025-30066"
        
    strings:
        // Memory dump patterns
        $mem1 = "/proc/self/mem"
        $mem2 = "Runner.Worker"
        $mem3 = /gcore\s+\d+/
        
        // Secret extraction
        $secret1 = "GITHUB_TOKEN"
        $secret2 = "NPM_TOKEN" 
        $secret3 = "AWS_ACCESS_KEY"
        
        // Base64 double encoding
        $b64 = /base64\s*-d.*base64\s*-d/
        
        // Workflow log exfiltration
        $log1 = "::set-output"
        $log2 = "echo.*>>"
        
    condition:
        (any of ($mem*) and any of ($secret*)) or
        ($b64) or
        (any of ($log*) and any of ($secret*))
}

rule NPM_Crypto_Wallet_Hijack {
    meta:
        description = "Detects npm crypto wallet hijacking (debug/chalk attack)"
        date = "2025-11-30"
        reference = "September 2025 npm supply chain attack"
        
    strings:
        // Wallet API hooks
        $wallet1 = "window.ethereum"
        $wallet2 = "window.solana"
        $wallet3 = "MetaMask"
        
        // Transaction interception
        $tx1 = "eth_sendTransaction"
        $tx2 = "signTransaction"
        $tx3 = "sendTransaction"
        
        // Address replacement patterns
        $addr1 = /0x[a-fA-F0-9]{40}/
        $addr2 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/  // Bitcoin
        
        // Network hooks
        $hook1 = "XMLHttpRequest.prototype"
        $hook2 = "fetch.prototype"
        $hook3 = "Request.prototype"
        
    condition:
        (any of ($wallet*) and any of ($tx*)) or
        (any of ($hook*) and any of ($addr*))
}
```

---

## Part 3: 21-Step Pipeline Integration

### 3.1 Pipeline Stage Mapping

```
JANUSEC 21-STEP PIPELINE - SUPPLY CHAIN ATTACK INTEGRATION

┌─────────────────────────────────────────────────────────────────────┐
│ STAGE 1-5: EVENT INGESTION & NORMALIZATION                          │
├─────────────────────────────────────────────────────────────────────┤
│ Step 1: Raw Event Ingestion                                         │
│   NEW: Add npm audit log ingestion                                  │
│   NEW: Add GitHub Actions workflow log ingestion                    │
│   NEW: Add package.json/yarn.lock change detection                  │
│                                                                     │
│ Step 2: Event Parsing                                               │
│   NEW: Parse npm lifecycle script execution (postinstall/preinstall)│
│   NEW: Parse GitHub Actions workflow YAML                           │
│   NEW: Parse package manifest changes                               │
│                                                                     │
│ Step 3: Event Normalization                                         │
│   NEW: Normalize package install events to UnifiedSecurityEvent     │
│   NEW: Normalize CI/CD pipeline events                              │
│                                                                     │
│ Step 4: Deduplication                                               │
│   Handle rapid npm install events from same package                 │
│                                                                     │
│ Step 5: Enrichment - Asset Context                                  │
│   NEW: Enrich with SBOM data                                        │
│   NEW: Enrich with package criticality (download count, maintainers)│
└─────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│ STAGE 6-10: DETECTION & ANALYSIS                                    │
├─────────────────────────────────────────────────────────────────────┤
│ Step 6: Signature-Based Detection                                   │
│   NEW: Supply chain YARA rules (Shai-Hulud, tj-actions, crypto)     │
│   NEW: Known malicious package hash lookup                          │
│   NEW: Typosquatting pattern matching                               │
│                                                                     │
│ Step 7: Behavioral Analysis                                         │
│   NEW: postinstall → shell spawn detection                          │
│   NEW: Credential file access patterns (.npmrc, .aws/credentials)   │
│   NEW: GitHub API calls from npm scripts                            │
│   NEW: Wiper behavior detection (rm -rf with network dependency)    │
│                                                                     │
│ Step 8: Anomaly Detection                                           │
│   NEW: Package version jump anomaly (v1.0.0 → v9.0.46 in hours)     │
│   NEW: Maintainer change anomaly                                    │
│   NEW: Dependency graph anomaly (new transitive deps)               │
│   NEW: Download spike correlation with CVE disclosure               │
│                                                                     │
│ Step 9: Threat Intelligence Correlation                             │
│   NEW: OSV database lookup (npm, PyPI, Go)                          │
│   NEW: Socket.dev malicious package feed                            │
│   NEW: Snyk vulnerability database                                  │
│                                                                     │
│ Step 10: Binary Analysis (NEW FOR SUPPLY CHAIN)                     │
│   Analyze dropped payloads from npm scripts                         │
│   Detect obfuscated JavaScript (webpack/babel abuse)                │
│   Entropy analysis for packed/encrypted payloads                    │
└─────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│ STAGE 11-15: CORRELATION & GRAPH ANALYSIS                           │
├─────────────────────────────────────────────────────────────────────┤
│ Step 11: HopGraph Node Creation                                     │
│   NEW: npm_package node type                                        │
│   NEW: github_action node type                                      │
│   NEW: ci_pipeline node type                                        │
│   NEW: package_maintainer node type                                 │
│                                                                     │
│ Step 12: HopGraph Edge Creation                                     │
│   NEW: depends_on (package → package)                               │
│   NEW: installs (host → package)                                    │
│   NEW: executes_script (package → process)                          │
│   NEW: publishes (maintainer → package)                             │
│   NEW: compromises (attacker → package)                             │
│                                                                     │
│ Step 13: Attack Path Analysis                                       │
│   NEW: Supply chain propagation path                                │
│   NEW: Blast radius calculation (downstream dependents)             │
│   NEW: CI/CD pipeline traversal                                     │
│                                                                     │
│ Step 14: Cross-Domain Correlation                                   │
│   npm attack → endpoint compromise → credential theft → lateral     │
│   GitHub Action compromise → CI secret leak → cloud access          │
│                                                                     │
│ Step 15: Pattern Detection                                          │
│   NEW: Shai-Hulud worm propagation pattern                          │
│   NEW: Dependency confusion pattern                                 │
│   NEW: Typosquatting cluster detection                              │
└─────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│ STAGE 16-18: LLM TRIAGE                                             │
├─────────────────────────────────────────────────────────────────────┤
│ Step 16: Context Assembly                                           │
│   Assemble supply chain context:                                    │
│   - Package name, version, maintainer history                       │
│   - Dependency tree (transitive deps)                               │
│   - Execution context (build vs runtime)                            │
│   - SBOM impact assessment                                          │
│                                                                     │
│ Step 17: Tier 1 LLM Summary                                         │
│   Generate initial triage summary (see Section 6)                   │
│                                                                     │
│ Step 18: Tier 1 Verdict                                             │
│   AUTO_CLOSE | ESCALATE_TIER_2 | CRITICAL_ALERT                     │
└─────────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│ STAGE 19-21: TIER 2 & RESPONSE                                      │
├─────────────────────────────────────────────────────────────────────┤
│ Step 19: Tier 2 Deep Analysis (if escalated)                        │
│   Full supply chain impact assessment                               │
│   SBOM-wide exposure analysis                                       │
│   Remediation plan generation                                       │
│                                                                     │
│ Step 20: Response Orchestration                                     │
│   NEW: Automated npm unpublish recommendation                       │
│   NEW: Lockfile rollback generation                                 │
│   NEW: GitHub Actions pin-to-SHA recommendation                     │
│   NEW: SBOM update notification                                     │
│                                                                     │
│ Step 21: Incident Documentation                                     │
│   Supply chain attack report generation                             │
│   SLSA level assessment                                             │
│   Compliance impact (SOC2, NIST SSDF)                               │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 New Pipeline Stage: Package Analysis

```python
"""
pipeline_supply_chain.py - Supply Chain Attack Detection Stage
Integrates into JanuSec 21-step pipeline between Steps 9-10
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import re


class PackageEcosystem(Enum):
    NPM = "npm"
    PYPI = "pypi"
    RUBYGEMS = "rubygems"
    GO = "go"
    CARGO = "cargo"
    MAVEN = "maven"
    NUGET = "nuget"


class SupplyChainThreatType(Enum):
    TYPOSQUATTING = "typosquatting"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    ACCOUNT_TAKEOVER = "account_takeover"
    MALICIOUS_POSTINSTALL = "malicious_postinstall"
    WORM_PROPAGATION = "worm_propagation"
    CREDENTIAL_THEFT = "credential_theft"
    CRYPTO_HIJACK = "crypto_hijack"
    CI_CD_COMPROMISE = "ci_cd_compromise"
    MAINTAINER_COMPROMISE = "maintainer_compromise"


@dataclass
class PackageInstallEvent:
    """Normalized package installation event"""
    timestamp: datetime
    host: str
    user: str
    ecosystem: PackageEcosystem
    package_name: str
    package_version: str
    install_method: str  # npm install, pip install, etc.
    lifecycle_scripts: List[str]  # postinstall, preinstall, etc.
    dependencies: List[str]
    source_registry: str
    lockfile_hash: Optional[str]
    
    
@dataclass
class SupplyChainThreat:
    """Detected supply chain threat"""
    threat_type: SupplyChainThreatType
    severity: str
    confidence: float
    package: str
    ecosystem: PackageEcosystem
    details: Dict[str, Any]
    iocs: List[str]
    mitre_techniques: List[str]
    affected_hosts: List[str]
    blast_radius: int  # Estimated downstream impact
    

class SupplyChainDetector:
    """
    Supply chain attack detector for 21-step pipeline.
    
    Detects:
    - Shai-Hulud worm variants
    - npm/PyPI credential theft
    - GitHub Actions compromise
    - Typosquatting
    - Dependency confusion
    - Maintainer account compromise
    """
    
    def __init__(self, threat_intel_client, sbom_service):
        self.threat_intel = threat_intel_client
        self.sbom = sbom_service
        
        # Known malicious patterns
        self.malicious_package_hashes = set()
        self.typosquat_targets = self._load_typosquat_targets()
        self.suspicious_maintainers = set()
        
        # Behavioral baselines
        self.package_install_baseline: Dict[str, Dict] = {}
        
    # ========================================================================
    # DETECTION: SHAI-HULUD WORM
    # ========================================================================
    
    def detect_shai_hulud(self, event: PackageInstallEvent, 
                          process_tree: List[Dict]) -> Optional[SupplyChainThreat]:
        """
        Detect Shai-Hulud npm worm (September/November 2025 variants).
        
        Indicators:
        - postinstall/preinstall script spawning shell
        - Access to .npmrc, .git-credentials
        - GitHub API calls for repo creation
        - npm publish from non-standard directory
        - Repository named "Shai-Hulud" or "Sha1-Hulud"
        """
        indicators = []
        severity = "medium"
        
        # Check lifecycle script execution
        if any(script in event.lifecycle_scripts for script in ['postinstall', 'preinstall']):
            # Look for shell spawn in process tree
            for proc in process_tree:
                if proc.get('name') in ['bash', 'sh', 'cmd.exe', 'powershell.exe']:
                    parent = proc.get('parent', '')
                    if 'node' in parent.lower() or 'npm' in parent.lower():
                        indicators.append('lifecycle_script_shell_spawn')
                        severity = "high"
        
        # Check for credential file access
        credential_files = ['.npmrc', '.git-credentials', '.aws/credentials', 
                          '.ssh/id_rsa', '.netrc']
        file_accesses = [p.get('file_accessed', '') for p in process_tree]
        
        for cred_file in credential_files:
            if any(cred_file in fa for fa in file_accesses):
                indicators.append(f'credential_access:{cred_file}')
                severity = "critical"
        
        # Check for GitHub API exfiltration
        network_calls = [p.get('network_dst', '') for p in process_tree]
        github_api_patterns = ['api.github.com/user/repos', 'api.github.com/repos']
        
        for pattern in github_api_patterns:
            if any(pattern in nc for nc in network_calls):
                indicators.append('github_api_exfil')
                severity = "critical"
        
        # Check for Shai-Hulud specific patterns
        command_lines = ' '.join([p.get('cmdline', '') for p in process_tree])
        
        if re.search(r'shai.?hulud', command_lines, re.IGNORECASE):
            indicators.append('shai_hulud_string')
            severity = "critical"
        
        # Check for npm publish from suspicious context
        if 'npm publish' in command_lines:
            # Check if publishing from temp or unexpected directory
            if any(d in command_lines for d in ['/tmp/', '/var/tmp/', 'AppData\\Local\\Temp']):
                indicators.append('suspicious_npm_publish')
                severity = "critical"
        
        # Shai-Hulud 2.0: Check for Bun runtime usage
        if any(f in command_lines for f in ['setup_bun.js', 'bun_environment.js']):
            indicators.append('shai_hulud_2_bun')
            severity = "critical"
        
        # Shai-Hulud 2.0: Check for wiper fallback
        wiper_patterns = ['rm -rf ~', 'rm -rf $HOME', 'rmdir /s /q %USERPROFILE%']
        if any(wp in command_lines for wp in wiper_patterns):
            indicators.append('wiper_behavior')
            severity = "critical"
        
        if indicators:
            return SupplyChainThreat(
                threat_type=SupplyChainThreatType.WORM_PROPAGATION,
                severity=severity,
                confidence=min(0.5 + (len(indicators) * 0.15), 0.98),
                package=event.package_name,
                ecosystem=event.ecosystem,
                details={
                    'indicators': indicators,
                    'version': event.package_version,
                    'lifecycle_scripts': event.lifecycle_scripts,
                },
                iocs=[event.package_name, f"{event.package_name}@{event.package_version}"],
                mitre_techniques=['T1195.002', 'T1059', 'T1552.001', 'T1567'],
                affected_hosts=[event.host],
                blast_radius=self._calculate_blast_radius(event.package_name, event.ecosystem)
            )
        
        return None
    
    # ========================================================================
    # DETECTION: CRYPTO WALLET HIJACKING (npm debug/chalk attack)
    # ========================================================================
    
    def detect_crypto_hijack(self, event: PackageInstallEvent,
                             js_analysis: Dict) -> Optional[SupplyChainThreat]:
        """
        Detect cryptocurrency wallet hijacking (September 2025 attack).
        
        Indicators:
        - window.ethereum hooks
        - Transaction interception
        - Address replacement
        - Fetch/XHR prototype modification
        """
        indicators = []
        
        # Analyze JavaScript content
        js_content = js_analysis.get('content', '')
        
        # Wallet API hooks
        wallet_apis = ['window.ethereum', 'window.solana', 'window.phantom',
                      'ethereum.request', 'solana.signTransaction']
        
        for api in wallet_apis:
            if api in js_content:
                indicators.append(f'wallet_api_access:{api}')
        
        # Transaction interception
        tx_methods = ['eth_sendTransaction', 'eth_signTransaction', 
                     'personal_sign', 'signTypedData']
        
        for method in tx_methods:
            if method in js_content:
                indicators.append(f'tx_interception:{method}')
        
        # Prototype modification (XHR/Fetch hooks)
        prototype_mods = ['XMLHttpRequest.prototype', 'fetch =', 
                        'Request.prototype', 'Response.prototype']
        
        for mod in prototype_mods:
            if mod in js_content:
                indicators.append(f'prototype_mod:{mod}')
        
        # Crypto address patterns
        eth_addresses = re.findall(r'0x[a-fA-F0-9]{40}', js_content)
        btc_addresses = re.findall(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', js_content)
        
        if len(eth_addresses) > 5:  # Multiple hardcoded addresses
            indicators.append(f'hardcoded_eth_addresses:{len(eth_addresses)}')
        if btc_addresses:
            indicators.append(f'hardcoded_btc_addresses:{len(btc_addresses)}')
        
        if len(indicators) >= 2:
            return SupplyChainThreat(
                threat_type=SupplyChainThreatType.CRYPTO_HIJACK,
                severity="critical",
                confidence=min(0.6 + (len(indicators) * 0.1), 0.95),
                package=event.package_name,
                ecosystem=event.ecosystem,
                details={
                    'indicators': indicators,
                    'eth_addresses': eth_addresses[:10],
                    'btc_addresses': btc_addresses[:10],
                },
                iocs=eth_addresses[:5] + btc_addresses[:5],
                mitre_techniques=['T1565.002', 'T1185', 'T1557'],
                affected_hosts=[event.host],
                blast_radius=self._calculate_blast_radius(event.package_name, event.ecosystem)
            )
        
        return None
    
    # ========================================================================
    # DETECTION: GITHUB ACTIONS COMPROMISE (tj-actions/reviewdog)
    # ========================================================================
    
    def detect_github_actions_compromise(self, workflow_event: Dict) -> Optional[SupplyChainThreat]:
        """
        Detect GitHub Actions supply chain compromise (March 2025 attacks).
        
        Indicators:
        - Memory dump commands (gcore, /proc/self/mem)
        - Secret extraction from runner environment
        - Double-encoded base64 in logs
        - Tag reference modification
        """
        indicators = []
        
        action_name = workflow_event.get('action', '')
        workflow_content = workflow_event.get('workflow_content', '')
        run_logs = workflow_event.get('logs', '')
        
        # Known compromised actions
        COMPROMISED_ACTIONS = [
            'tj-actions/changed-files',
            'tj-actions/eslint-changed-files',
            'reviewdog/action-setup',
            'reviewdog/action-shellcheck',
            'reviewdog/action-staticcheck',
        ]
        
        for compromised in COMPROMISED_ACTIONS:
            if compromised in action_name or compromised in workflow_content:
                indicators.append(f'known_compromised_action:{compromised}')
        
        # Memory dump detection
        mem_dump_patterns = ['/proc/self/mem', 'gcore', 'Runner.Worker', 
                           'ProcessMemoryDumper']
        
        for pattern in mem_dump_patterns:
            if pattern in run_logs or pattern in workflow_content:
                indicators.append(f'memory_dump:{pattern}')
        
        # Secret extraction in logs
        secret_patterns = [
            (r'GITHUB_TOKEN\s*[:=]', 'github_token'),
            (r'NPM_TOKEN\s*[:=]', 'npm_token'),
            (r'AWS_ACCESS_KEY', 'aws_key'),
            (r'ghp_[a-zA-Z0-9]{36}', 'github_pat'),
            (r'npm_[a-zA-Z0-9]{36}', 'npm_auth'),
        ]
        
        for pattern, name in secret_patterns:
            if re.search(pattern, run_logs):
                indicators.append(f'secret_in_logs:{name}')
        
        # Double-encoded base64 (specific to tj-actions attack)
        if re.search(r'base64\s*-d.*base64\s*-d', run_logs):
            indicators.append('double_base64_encoding')
        
        # Tag reference without SHA pinning
        tag_patterns = re.findall(r'uses:\s*([^@]+)@(v\d+|main|master)', workflow_content)
        for action, tag in tag_patterns:
            if tag in ['v1', 'v2', 'v3', 'main', 'master']:
                indicators.append(f'mutable_tag_reference:{action}@{tag}')
        
        if indicators:
            severity = "critical" if any('secret_in_logs' in i or 'memory_dump' in i for i in indicators) else "high"
            
            return SupplyChainThreat(
                threat_type=SupplyChainThreatType.CI_CD_COMPROMISE,
                severity=severity,
                confidence=min(0.5 + (len(indicators) * 0.15), 0.95),
                package=action_name,
                ecosystem=PackageEcosystem.NPM,  # GitHub Actions
                details={
                    'indicators': indicators,
                    'workflow': workflow_event.get('workflow_name'),
                    'repository': workflow_event.get('repository'),
                },
                iocs=[action_name],
                mitre_techniques=['T1195.002', 'T1552.001', 'T1059.004'],
                affected_hosts=[workflow_event.get('runner_name', 'unknown')],
                blast_radius=len(workflow_event.get('downstream_repos', []))
            )
        
        return None
    
    # ========================================================================
    # DETECTION: TYPOSQUATTING
    # ========================================================================
    
    def detect_typosquatting(self, event: PackageInstallEvent) -> Optional[SupplyChainThreat]:
        """
        Detect typosquatting packages.
        
        Common patterns:
        - Character transposition (lodash → lodashs)
        - Missing/extra characters (express → expresss)
        - Homoglyphs (l → 1, o → 0)
        - Hyphenation changes (lodash → lo-dash)
        """
        from difflib import SequenceMatcher
        
        package = event.package_name.lower()
        
        for legit_package in self.typosquat_targets:
            # Skip exact match
            if package == legit_package:
                continue
            
            similarity = SequenceMatcher(None, package, legit_package).ratio()
            
            # High similarity but not exact = potential typosquat
            if 0.85 <= similarity < 1.0:
                # Additional checks
                edit_distance = self._levenshtein_distance(package, legit_package)
                
                if edit_distance <= 2:
                    return SupplyChainThreat(
                        threat_type=SupplyChainThreatType.TYPOSQUATTING,
                        severity="high",
                        confidence=0.7 + (similarity * 0.2),
                        package=event.package_name,
                        ecosystem=event.ecosystem,
                        details={
                            'target_package': legit_package,
                            'similarity': similarity,
                            'edit_distance': edit_distance,
                        },
                        iocs=[event.package_name],
                        mitre_techniques=['T1195.002', 'T1204.002'],
                        affected_hosts=[event.host],
                        blast_radius=0  # Unknown until executed
                    )
        
        return None
    
    # ========================================================================
    # DETECTION: DEPENDENCY CONFUSION
    # ========================================================================
    
    def detect_dependency_confusion(self, event: PackageInstallEvent,
                                    internal_packages: Set[str]) -> Optional[SupplyChainThreat]:
        """
        Detect dependency confusion attacks.
        
        Attack pattern:
        - Attacker publishes package with same name as internal package
        - Public version number is higher than internal
        - Package manager installs public version
        """
        # Check if package name matches internal package
        if event.package_name in internal_packages:
            # Check if source is public registry
            public_registries = ['registry.npmjs.org', 'pypi.org', 'rubygems.org']
            
            if any(reg in event.source_registry for reg in public_registries):
                return SupplyChainThreat(
                    threat_type=SupplyChainThreatType.DEPENDENCY_CONFUSION,
                    severity="critical",
                    confidence=0.85,
                    package=event.package_name,
                    ecosystem=event.ecosystem,
                    details={
                        'internal_package_name': event.package_name,
                        'installed_from': event.source_registry,
                        'version': event.package_version,
                    },
                    iocs=[event.package_name],
                    mitre_techniques=['T1195.002', 'T1199'],
                    affected_hosts=[event.host],
                    blast_radius=len(internal_packages)
                )
        
        return None
    
    # ========================================================================
    # HELPER METHODS
    # ========================================================================
    
    def _calculate_blast_radius(self, package_name: str, ecosystem: PackageEcosystem) -> int:
        """Calculate downstream impact of compromised package."""
        # Query npm/PyPI for dependent count
        # In production, query actual registry API
        return self.sbom.get_dependent_count(package_name, ecosystem.value)
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate edit distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _load_typosquat_targets(self) -> Set[str]:
        """Load list of popular packages to check for typosquatting."""
        # Top npm packages by download count
        return {
            'lodash', 'react', 'express', 'axios', 'moment', 'chalk', 'debug',
            'commander', 'request', 'async', 'underscore', 'bluebird', 'uuid',
            'webpack', 'babel', 'typescript', 'eslint', 'prettier', 'jest',
            'mocha', 'chai', 'sinon', 'mongoose', 'sequelize', 'pg', 'mysql',
            'redis', 'socket.io', 'cors', 'dotenv', 'nodemon', 'pm2',
            # ... extend with top 1000 packages
        }
```

---

## Part 4: HopGraph Supply Chain Schema

### 4.1 New Node Types

```python
"""
hopgraph_supply_chain_nodes.py - Supply chain attack graph schema
"""

SUPPLY_CHAIN_NODE_TYPES = {
    # Package ecosystem nodes
    'npm_package': {
        'ttl': 30 * 24 * 3600,  # 30 days
        'criticality_base': 0.5,
        'attributes': [
            'name', 'version', 'registry', 'maintainers',
            'weekly_downloads', 'dependencies', 'devDependencies',
            'lifecycle_scripts', 'repository', 'published_at',
            'deprecated', 'unpublished'
        ],
        'cross_domain_keys': ['name', 'registry']
    },
    
    'pypi_package': {
        'ttl': 30 * 24 * 3600,
        'criticality_base': 0.5,
        'attributes': [
            'name', 'version', 'maintainer', 'requires_dist',
            'setup_py_content', 'classifiers'
        ],
    },
    
    'package_maintainer': {
        'ttl': 90 * 24 * 3600,  # 90 days
        'criticality_base': 0.6,
        'attributes': [
            'username', 'email', 'registry', 'packages_maintained',
            'account_created', 'mfa_enabled', 'verified'
        ],
    },
    
    'github_action': {
        'ttl': 30 * 24 * 3600,
        'criticality_base': 0.7,
        'attributes': [
            'owner', 'repo', 'version_tag', 'commit_sha',
            'permissions_required', 'composite_actions'
        ],
    },
    
    'ci_pipeline': {
        'ttl': 7 * 24 * 3600,  # 7 days
        'criticality_base': 0.8,
        'attributes': [
            'platform', 'repository', 'workflow_name',
            'triggers', 'secrets_used', 'artifacts_produced'
        ],
    },
    
    'sbom': {
        'ttl': 7 * 24 * 3600,
        'criticality_base': 0.4,
        'attributes': [
            'format', 'components', 'relationships',
            'created_at', 'tool', 'hash'
        ],
    },
    
    'package_registry': {
        'ttl': 90 * 24 * 3600,
        'criticality_base': 0.3,
        'attributes': ['name', 'url', 'type'],  # npm, pypi, private
    },
}

SUPPLY_CHAIN_EDGE_TYPES = {
    # Dependency relationships
    'depends_on': {
        'src': 'npm_package',
        'dst': 'npm_package',
        'weight': 0.5,
        'attributes': ['version_constraint', 'dependency_type'],  # prod, dev, peer
    },
    
    'transitively_depends_on': {
        'src': 'npm_package',
        'dst': 'npm_package',
        'weight': 0.3,
        'attributes': ['depth', 'path'],
    },
    
    # Installation relationships
    'installs': {
        'src': 'host',
        'dst': 'npm_package',
        'weight': 0.6,
        'mitre': ['T1195.002'],
        'attributes': ['install_time', 'method', 'user'],
    },
    
    # Execution relationships
    'executes_lifecycle_script': {
        'src': 'npm_package',
        'dst': 'process',
        'weight': 0.8,
        'mitre': ['T1059'],
        'attributes': ['script_type', 'script_content'],
    },
    
    # Maintainer relationships
    'maintained_by': {
        'src': 'npm_package',
        'dst': 'package_maintainer',
        'weight': 0.5,
    },
    
    'publishes': {
        'src': 'package_maintainer',
        'dst': 'npm_package',
        'weight': 0.6,
        'mitre': ['T1195.002'],
        'attributes': ['publish_time', 'version'],
    },
    
    # Compromise relationships
    'compromises': {
        'src': 'threat_actor',
        'dst': 'npm_package',
        'weight': 0.95,
        'mitre': ['T1195.002'],
    },
    
    'compromises_maintainer': {
        'src': 'threat_actor',
        'dst': 'package_maintainer',
        'weight': 0.95,
        'mitre': ['T1078'],
    },
    
    # CI/CD relationships
    'uses_action': {
        'src': 'ci_pipeline',
        'dst': 'github_action',
        'weight': 0.6,
        'attributes': ['version_ref', 'pinned_sha'],
    },
    
    'produces_artifact': {
        'src': 'ci_pipeline',
        'dst': 'binary',
        'weight': 0.5,
    },
    
    'exposes_secret': {
        'src': 'ci_pipeline',
        'dst': 'credential',
        'weight': 0.95,
        'mitre': ['T1552.001'],
    },
    
    # Supply chain propagation
    'propagates_to': {
        'src': 'npm_package',
        'dst': 'npm_package',
        'weight': 0.9,
        'mitre': ['T1195.002'],
        'description': 'Worm propagation (Shai-Hulud style)',
    },
    
    # Registry relationships
    'published_to': {
        'src': 'npm_package',
        'dst': 'package_registry',
        'weight': 0.4,
    },
    
    # SBOM relationships
    'included_in': {
        'src': 'npm_package',
        'dst': 'sbom',
        'weight': 0.3,
    },
}


# Critical graph queries for supply chain attack detection
SUPPLY_CHAIN_GRAPH_QUERIES = {
    'shai_hulud_propagation': """
        MATCH path = (p1:npm_package)-[:propagates_to*1..10]->(p2:npm_package)
        WHERE p1.compromised = true
        RETURN path, length(path) as depth
        ORDER BY depth DESC
    """,
    
    'blast_radius': """
        MATCH (p:npm_package {name: $package_name})<-[:depends_on*1..5]-(dependent:npm_package)
        RETURN p, collect(dependent) as affected_packages, count(dependent) as blast_radius
    """,
    
    'compromised_maintainer_packages': """
        MATCH (m:package_maintainer)<-[:maintained_by]-(p:npm_package)
        WHERE m.compromised = true
        RETURN m, collect(p) as potentially_compromised_packages
    """,
    
    'ci_cd_secret_exposure': """
        MATCH path = (pipeline:ci_pipeline)-[:uses_action]->(action:github_action)
                     -[:executes]->(proc:process)
                     -[:accesses]->(cred:credential)
        WHERE action.compromised = true
        RETURN path
    """,
    
    'dependency_confusion_risk': """
        MATCH (pub:npm_package)-[:published_to]->(registry:package_registry {type: 'public'})
        MATCH (priv:npm_package)-[:published_to]->(registry2:package_registry {type: 'private'})
        WHERE pub.name = priv.name
        RETURN pub, priv, pub.version as public_version, priv.version as private_version
    """,
    
    'typosquat_cluster': """
        MATCH (p:npm_package)
        WHERE p.similarity_to_popular > 0.85 AND p.weekly_downloads < 100
        RETURN p, p.similar_to as target_package
    """,
}
```

---

## Part 5: Binary Analysis Integration

### 5.1 Package Payload Analysis

```python
"""
binary_supply_chain.py - Binary analysis for supply chain payloads
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class PackagePayloadAnalysis:
    """Analysis result for package payload/script"""
    package_name: str
    package_version: str
    payload_type: str  # 'js', 'py', 'sh', 'pe', 'elf'
    entropy: float
    obfuscation_detected: bool
    obfuscation_type: Optional[str]
    suspicious_strings: List[str]
    network_indicators: List[str]
    file_indicators: List[str]
    yara_matches: List[str]
    risk_score: float


class SupplyChainPayloadAnalyzer:
    """
    Analyze payloads dropped by supply chain attacks.
    
    Integrates with JanuSec binary analysis pipeline.
    """
    
    def analyze_npm_package(self, package_path: str) -> PackagePayloadAnalysis:
        """
        Analyze npm package contents for malicious payloads.
        
        Checks:
        - package.json lifecycle scripts
        - Obfuscated JavaScript
        - Embedded binaries
        - Network beacons
        - Credential access patterns
        """
        results = {
            'suspicious_strings': [],
            'network_indicators': [],
            'file_indicators': [],
            'yara_matches': [],
        }
        
        # 1. Analyze package.json
        package_json = self._read_package_json(package_path)
        if package_json:
            scripts = package_json.get('scripts', {})
            
            # Check lifecycle scripts
            dangerous_scripts = ['preinstall', 'postinstall', 'preuninstall', 
                               'postuninstall', 'prepublish', 'prepare']
            
            for script_name in dangerous_scripts:
                if script_name in scripts:
                    script_content = scripts[script_name]
                    
                    # Analyze script content
                    if self._is_suspicious_script(script_content):
                        results['suspicious_strings'].append(
                            f'{script_name}: {script_content[:100]}...'
                        )
        
        # 2. Analyze JavaScript files
        js_files = self._find_files(package_path, ['.js', '.mjs', '.cjs'])
        
        for js_file in js_files:
            js_analysis = self._analyze_javascript(js_file)
            
            if js_analysis.get('obfuscated'):
                results['suspicious_strings'].append(f'Obfuscated JS: {js_file}')
            
            results['network_indicators'].extend(js_analysis.get('urls', []))
            results['file_indicators'].extend(js_analysis.get('file_paths', []))
        
        # 3. Check for embedded binaries
        binary_files = self._find_files(package_path, ['.exe', '.dll', '.so', '.dylib'])
        
        for binary in binary_files:
            results['suspicious_strings'].append(f'Embedded binary: {binary}')
            
            # Run full binary analysis
            binary_analysis = self._analyze_binary(binary)
            results['yara_matches'].extend(binary_analysis.get('yara_matches', []))
        
        # 4. Calculate risk score
        risk_score = self._calculate_risk_score(results)
        
        return PackagePayloadAnalysis(
            package_name=package_json.get('name', 'unknown'),
            package_version=package_json.get('version', 'unknown'),
            payload_type='npm',
            entropy=self._calculate_entropy(package_path),
            obfuscation_detected=bool(results['suspicious_strings']),
            obfuscation_type=self._detect_obfuscation_type(js_files),
            suspicious_strings=results['suspicious_strings'],
            network_indicators=results['network_indicators'],
            file_indicators=results['file_indicators'],
            yara_matches=results['yara_matches'],
            risk_score=risk_score
        )
    
    def _is_suspicious_script(self, script: str) -> bool:
        """Check if lifecycle script is suspicious."""
        suspicious_patterns = [
            'curl', 'wget', 'powershell', 'cmd /c', 'bash -c',
            'eval(', 'exec(', 'child_process', 'spawn(',
            '/tmp/', '/var/tmp/', 'AppData\\Local\\Temp',
            'base64', 'atob(', 'Buffer.from(',
            '.npmrc', '.git-credentials', '.aws/',
            'api.github.com', 'webhook.site',
        ]
        
        script_lower = script.lower()
        return any(pattern.lower() in script_lower for pattern in suspicious_patterns)
    
    def _analyze_javascript(self, file_path: str) -> Dict[str, Any]:
        """Analyze JavaScript file for malicious patterns."""
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
        
        results = {
            'obfuscated': False,
            'urls': [],
            'file_paths': [],
        }
        
        # Detect obfuscation
        obfuscation_indicators = [
            # Webpack/babel artifacts
            r'__webpack_require__',
            # String obfuscation
            r'\\x[0-9a-f]{2}',
            r'\\u[0-9a-f]{4}',
            # Heavy use of eval
            r'eval\s*\(',
            # Function constructor
            r'Function\s*\(',
            # Long encoded strings
            r'[a-zA-Z0-9+/=]{100,}',
        ]
        
        import re
        for pattern in obfuscation_indicators:
            if re.search(pattern, content):
                results['obfuscated'] = True
                break
        
        # Extract URLs
        url_pattern = r'https?://[^\s\'"<>]+'
        results['urls'] = re.findall(url_pattern, content)
        
        # Extract file paths
        path_patterns = [
            r'/etc/passwd',
            r'/etc/shadow',
            r'\.npmrc',
            r'\.git-credentials',
            r'\.aws/credentials',
            r'\.ssh/id_rsa',
            r'%USERPROFILE%',
            r'%APPDATA%',
        ]
        
        for pattern in path_patterns:
            if pattern in content:
                results['file_paths'].append(pattern)
        
        return results
    
    def _calculate_risk_score(self, results: Dict) -> float:
        """Calculate overall risk score for package."""
        score = 0.0
        
        # Suspicious strings
        score += min(len(results['suspicious_strings']) * 0.1, 0.3)
        
        # Network indicators
        score += min(len(results['network_indicators']) * 0.05, 0.2)
        
        # File access indicators
        credential_files = ['.npmrc', '.git-credentials', '.aws/', '.ssh/']
        cred_access = sum(1 for f in results['file_indicators'] 
                        if any(cf in f for cf in credential_files))
        score += cred_access * 0.15
        
        # YARA matches
        score += min(len(results['yara_matches']) * 0.2, 0.4)
        
        return min(score, 1.0)
```

---

## Part 6: Tier 1 & Tier 2 LLM Prompts

### 6.1 Tier 1 Supply Chain Triage Prompt

```python
"""
llm_supply_chain_prompts.py - LLM prompts for supply chain attack triage
"""

TIER1_SUPPLY_CHAIN_PROMPT = """
You are a security analyst triaging a potential supply chain attack alert.

## Alert Context
- **Package**: {package_name}@{package_version}
- **Ecosystem**: {ecosystem}
- **Host**: {host}
- **User**: {user}
- **Timestamp**: {timestamp}
- **Detection Source**: {detection_source}

## Detection Details
{detection_details}

## Process Tree (from npm install)
```
{process_tree}
```

## Network Activity (post-install)
{network_activity}

## File Access (post-install)
{file_access}

## Package Metadata
- **Weekly Downloads**: {weekly_downloads}
- **Maintainers**: {maintainers}
- **Published**: {published_at}
- **Dependencies**: {dependency_count}
- **Lifecycle Scripts**: {lifecycle_scripts}

## Known Threat Intelligence
{threat_intel}

## SBOM Impact
- **Applications using this package**: {sbom_apps}
- **Transitive dependents**: {transitive_count}

---

## Your Task

Provide a concise triage summary with:

1. **VERDICT**: [BENIGN | SUSPICIOUS | MALICIOUS | REQUIRES_INVESTIGATION]

2. **CONFIDENCE**: [LOW | MEDIUM | HIGH] with percentage

3. **ATTACK TYPE** (if applicable):
   - Typosquatting
   - Dependency Confusion
   - Maintainer Account Compromise
   - Malicious Postinstall/Preinstall
   - Credential Theft (Shai-Hulud style)
   - Crypto Wallet Hijack
   - CI/CD Compromise
   - Unknown/Novel

4. **KEY INDICATORS** (bullet points, max 5)

5. **BLAST RADIUS**: Number of potentially affected systems/applications

6. **IMMEDIATE RISK**: What's at risk RIGHT NOW?

7. **RECOMMENDED ACTION**:
   - AUTO_CLOSE (false positive)
   - ESCALATE_TIER_2 (needs deeper analysis)
   - CRITICAL_ALERT (immediate response required)
   - ISOLATE_HOST (contain spread)

8. **ONE-SENTENCE SUMMARY** for SOC dashboard

---

Keep your response under 500 words. Be specific and actionable.
"""


TIER2_SUPPLY_CHAIN_PROMPT = """
You are a senior security analyst conducting deep investigation of a supply chain attack.

## Escalation Context
{tier1_summary}

## Full Package Analysis
### package.json
```json
{package_json}
```

### Lifecycle Script Content
```bash
{lifecycle_script_content}
```

### JavaScript Analysis
- **Entropy**: {js_entropy}
- **Obfuscation Type**: {obfuscation_type}
- **Suspicious Functions**: {suspicious_functions}

### Binary Payloads (if any)
{binary_analysis}

## Full Network Capture Summary
{network_pcap_summary}

## Full Process Tree with Command Lines
```
{full_process_tree}
```

## File System Changes
{filesystem_changes}

## Credential Access Attempts
{credential_access}

## HopGraph Attack Path
```
{hopgraph_path}
```

## Cross-Host Propagation (if Shai-Hulud)
{propagation_analysis}

## Historical Context
- **Previous versions malicious?**: {version_history}
- **Maintainer account history**: {maintainer_history}
- **Similar packages detected**: {similar_packages}

---

## Your Task

Provide a comprehensive investigation report:

### 1. EXECUTIVE SUMMARY (3-5 sentences)
What happened, what's the impact, what should leadership know?

### 2. TECHNICAL ANALYSIS
- Attack vector and entry point
- Payload analysis
- Persistence mechanisms
- Data exfiltration methods
- Lateral movement (if any)

### 3. MITRE ATT&CK MAPPING
Map observed behaviors to MITRE techniques.

### 4. INDICATORS OF COMPROMISE (IOCs)
- Package names/versions
- File hashes
- Network indicators (IPs, domains, URLs)
- File paths
- Registry keys (if Windows)
- Process names

### 5. BLAST RADIUS ASSESSMENT
- Directly affected hosts
- Potentially affected hosts (same package installed)
- Downstream applications
- CI/CD pipelines using this package/action

### 6. CONTAINMENT RECOMMENDATIONS
Step-by-step actions to contain the threat.

### 7. REMEDIATION STEPS
How to clean affected systems and prevent recurrence.

### 8. DETECTION RULES
Provide specific detection rules:
- YARA rule for payload
- Sigma rule for behavior
- Network IOC blocklist

### 9. LESSONS LEARNED
What can be improved to prevent similar attacks?

---

Be thorough but concise. Use bullet points where appropriate.
"""


def generate_tier1_prompt(alert_data: Dict) -> str:
    """Generate Tier 1 prompt from alert data."""
    return TIER1_SUPPLY_CHAIN_PROMPT.format(
        package_name=alert_data.get('package_name', 'unknown'),
        package_version=alert_data.get('package_version', 'unknown'),
        ecosystem=alert_data.get('ecosystem', 'npm'),
        host=alert_data.get('host', 'unknown'),
        user=alert_data.get('user', 'unknown'),
        timestamp=alert_data.get('timestamp', 'unknown'),
        detection_source=alert_data.get('detection_source', 'unknown'),
        detection_details=alert_data.get('detection_details', 'N/A'),
        process_tree=alert_data.get('process_tree', 'N/A'),
        network_activity=alert_data.get('network_activity', 'N/A'),
        file_access=alert_data.get('file_access', 'N/A'),
        weekly_downloads=alert_data.get('weekly_downloads', 'unknown'),
        maintainers=alert_data.get('maintainers', 'unknown'),
        published_at=alert_data.get('published_at', 'unknown'),
        dependency_count=alert_data.get('dependency_count', 'unknown'),
        lifecycle_scripts=alert_data.get('lifecycle_scripts', 'none'),
        threat_intel=alert_data.get('threat_intel', 'No matches'),
        sbom_apps=alert_data.get('sbom_apps', 'unknown'),
        transitive_count=alert_data.get('transitive_count', 'unknown'),
    )
```

### 6.2 Example LLM Output

```
## TIER 1 TRIAGE SUMMARY

**VERDICT**: MALICIOUS
**CONFIDENCE**: HIGH (92%)

**ATTACK TYPE**: Credential Theft (Shai-Hulud variant)

**KEY INDICATORS**:
• postinstall script spawns /bin/bash with curl command
• Accesses .npmrc and .git-credentials files
• Makes POST request to api.github.com/user/repos
• Package version jumped from 1.0.0 to 9.0.46 in 2 hours
• Maintainer account created 3 days ago

**BLAST RADIUS**: 
• 1 host directly affected
• 47 hosts with same package in SBOM
• 12 CI/CD pipelines use this package

**IMMEDIATE RISK**:
• npm tokens likely exfiltrated
• GitHub PATs may be compromised
• Cloud credentials at risk if present in environment

**RECOMMENDED ACTION**: CRITICAL_ALERT + ISOLATE_HOST

**ONE-SENTENCE SUMMARY**: 
Shai-Hulud-style credential theft worm detected via @operato/board@9.0.46 postinstall script exfiltrating tokens to attacker-controlled GitHub repository.
```

---

## Part 7: Correlation Rules

### 7.1 Supply Chain Correlation Rules

```yaml
# correlation_rules_supply_chain.yaml

rules:
  # ========================================================================
  # SHAI-HULUD WORM DETECTION
  # ========================================================================
  - id: R_SC_SHAI_HULUD_001
    name: "Shai-Hulud NPM Worm - Credential Exfiltration"
    description: "Detects Shai-Hulud worm credential theft pattern"
    severity: critical
    mitre:
      - T1195.002  # Supply Chain Compromise
      - T1552.001  # Credentials In Files
      - T1567      # Exfiltration Over Web Service
    
    conditions:
      - type: sequence
        window: 5m
        events:
          - event_type: process_create
            filter:
              parent_image: "*node*"
              image: ["*bash*", "*sh*", "*cmd.exe*"]
          - event_type: file_access
            filter:
              file_path: ["*.npmrc*", "*.git-credentials*", "*.aws/credentials*"]
          - event_type: network_connection
            filter:
              dst_host: "api.github.com"
              dst_path: "*/repos*"
    
    actions:
      - isolate_host
      - revoke_npm_tokens
      - alert_critical
    
    hopgraph:
      create_edges:
        - type: "credential_exfiltration"
          src: "$host"
          dst: "github.com"
  
  # ========================================================================
  # SHAI-HULUD 2.0 - WIPER FALLBACK
  # ========================================================================
  - id: R_SC_SHAI_HULUD_002
    name: "Shai-Hulud 2.0 - Wiper Behavior"
    description: "Detects Shai-Hulud 2.0 destructive fallback"
    severity: critical
    
    conditions:
      - type: sequence
        window: 2m
        events:
          - event_type: network_connection
            filter:
              dst_host: ["api.github.com", "registry.npmjs.org"]
              status: "failed"
          - event_type: process_create
            filter:
              cmdline: ["*rm -rf ~*", "*rm -rf $HOME*", "*rmdir /s /q*"]
    
    actions:
      - isolate_host_immediate
      - snapshot_filesystem
      - alert_critical
  
  # ========================================================================
  # GITHUB ACTIONS COMPROMISE
  # ========================================================================
  - id: R_SC_GITHUB_ACTIONS_001
    name: "GitHub Actions Memory Dump Attack"
    description: "Detects tj-actions/reviewdog style memory dump"
    severity: critical
    mitre:
      - T1552.001
      - T1059.004
    
    conditions:
      - type: match_any
        events:
          - event_type: github_workflow_log
            filter:
              content_contains: ["/proc/self/mem", "Runner.Worker", "gcore"]
          - event_type: github_workflow_log
            filter:
              content_regex: "base64\\s*-d.*base64\\s*-d"
          - event_type: github_workflow_log
            filter:
              content_regex: "(ghp_[a-zA-Z0-9]{36}|npm_[a-zA-Z0-9]{36})"
    
    actions:
      - rotate_github_secrets
      - rotate_npm_tokens
      - alert_critical
  
  # ========================================================================
  # CRYPTO WALLET HIJACK
  # ========================================================================
  - id: R_SC_CRYPTO_HIJACK_001
    name: "NPM Crypto Wallet Hijacking"
    description: "Detects browser-based crypto wallet hijacking"
    severity: high
    
    conditions:
      - type: static_analysis
        target: npm_package
        checks:
          - js_contains: ["window.ethereum", "eth_sendTransaction"]
          - js_contains: ["XMLHttpRequest.prototype", "fetch ="]
          - js_contains_regex: "0x[a-fA-F0-9]{40}"
          - entropy: "> 7.0"
    
    actions:
      - quarantine_package
      - alert_security_team
  
  # ========================================================================
  # TYPOSQUATTING DETECTION
  # ========================================================================
  - id: R_SC_TYPOSQUAT_001
    name: "NPM Typosquatting Detection"
    description: "Detects installation of typosquatted packages"
    severity: high
    
    conditions:
      - type: package_install
        checks:
          - similarity_to_popular: "> 0.85"
          - exact_match: false
          - weekly_downloads: "< 1000"
          - age_days: "< 30"
    
    actions:
      - block_install
      - alert_developer
  
  # ========================================================================
  # DEPENDENCY CONFUSION
  # ========================================================================
  - id: R_SC_DEP_CONFUSION_001
    name: "Dependency Confusion Attack"
    description: "Public package installed matching internal package name"
    severity: critical
    
    conditions:
      - type: package_install
        checks:
          - package_name_in: "$INTERNAL_PACKAGE_LIST"
          - registry: "registry.npmjs.org"
    
    actions:
      - block_install
      - alert_security_team
      - create_incident
  
  # ========================================================================
  # MULTI-HOST PROPAGATION
  # ========================================================================
  - id: R_SC_PROPAGATION_001
    name: "Supply Chain Worm Propagation"
    description: "Same malicious package appearing on multiple hosts"
    severity: critical
    
    conditions:
      - type: aggregation
        window: 30m
        group_by: package_name
        having:
          distinct_hosts: "> 5"
          all_have:
            - lifecycle_script_executed: true
    
    actions:
      - isolate_all_affected_hosts
      - revoke_all_npm_tokens
      - alert_incident_response
```

---

## Part 8: What's Still Missing

### 8.1 Gaps Not Addressed

```python
REMAINING_GAPS = {
    'pre_execution_package_scanning': {
        'description': 'Scan packages BEFORE npm install executes',
        'solution': 'Integrate GuardDog/Socket.dev at registry proxy level',
        'effort': 'HIGH',
        'priority': 'P0'
    },
    
    'slsa_provenance_verification': {
        'description': 'Verify package was built from claimed source',
        'solution': 'Integrate Sigstore/in-toto attestation verification',
        'effort': 'HIGH',
        'priority': 'P1'
    },
    
    'private_registry_monitoring': {
        'description': 'Monitor internal npm/PyPI registries',
        'solution': 'Add private registry log ingestion',
        'effort': 'MEDIUM',
        'priority': 'P1'
    },
    
    'lockfile_integrity': {
        'description': 'Detect unauthorized lockfile modifications',
        'solution': 'Git hook + CI check for lockfile changes',
        'effort': 'LOW',
        'priority': 'P0'
    },
    
    'browser_runtime_protection': {
        'description': 'Detect crypto hijacking in browser context',
        'solution': 'Browser extension or CSP monitoring',
        'effort': 'HIGH',
        'priority': 'P2'
    },
    
    'sbom_continuous_monitoring': {
        'description': 'Alert when SBOM component becomes compromised',
        'solution': 'OSV feed integration with SBOM diffing',
        'effort': 'MEDIUM',
        'priority': 'P0'
    },
    
    'maintainer_takeover_detection': {
        'description': 'Detect when package maintainer changes suspiciously',
        'solution': 'npm registry webhook + maintainer change alerting',
        'effort': 'MEDIUM',
        'priority': 'P1'
    },
    
    'ai_generated_malware_detection': {
        'description': 'Detect LLM-generated malicious scripts (Shai-Hulud)',
        'solution': 'Train classifier on LLM output patterns',
        'effort': 'HIGH',
        'priority': 'P2'
    },
}
```

### 8.2 Recommended Implementation Roadmap

```
PHASE 1 (Weeks 1-2): Foundation
├── Add npm lifecycle script monitoring to EDR
├── Create supply chain node types in HopGraph
├── Implement Shai-Hulud YARA rules
├── Add OSV database integration
└── Deliverable: Detect known supply chain attacks post-execution

PHASE 2 (Weeks 3-4): Pre-Execution Detection
├── Integrate GuardDog for static package analysis
├── Add lockfile change detection
├── Implement typosquatting detector
├── Add dependency confusion checks
└── Deliverable: Block malicious packages before execution

PHASE 3 (Weeks 5-6): CI/CD Integration
├── GitHub Actions workflow log ingestion
├── Implement tj-actions/reviewdog detection rules
├── Add GitHub audit log monitoring
├── Create CI/CD pipeline node types in HopGraph
└── Deliverable: Detect CI/CD compromise in real-time

PHASE 4 (Weeks 7-8): Advanced Detection
├── Implement propagation tracking (worm detection)
├── Add SBOM continuous monitoring
├── Integrate Sigstore attestation verification
├── Add maintainer change alerting
└── Deliverable: Proactive supply chain threat detection

PHASE 5 (Weeks 9-10): Response Automation
├── Automated npm token revocation
├── Lockfile rollback generation
├── SHA pinning recommendations
├── Incident report generation
└── Deliverable: Automated supply chain incident response
```

---

## Part 9: Competitive Positioning

### JanuSec vs. Competitors

| Capability | JanuSec | Snyk | Socket.dev | Dependabot | Endor Labs |
|------------|---------|------|------------|------------|------------|
| **Pre-Install Scanning** | ⚠️ Gap | ✅ | ✅ | ❌ | ✅ |
| **Post-Install Behavior** | ✅ Strong | ❌ | ⚠️ Limited | ❌ | ⚠️ Limited |
| **Runtime Detection** | ✅ Strong | ❌ | ❌ | ❌ | ❌ |
| **HopGraph Correlation** | ✅ Unique | ❌ | ❌ | ❌ | ⚠️ Limited |
| **LLM Triage** | ✅ Unique | ❌ | ❌ | ❌ | ❌ |
| **CI/CD Monitoring** | ✅ (with gaps) | ⚠️ | ⚠️ | ✅ | ⚠️ |
| **SBOM Tracking** | ✅ | ✅ | ⚠️ | ❌ | ✅ |
| **Cross-Domain Correlation** | ✅ Unique | ❌ | ❌ | ❌ | ❌ |

### JanuSec Differentiators

1. **Runtime Behavioral Detection**: Most competitors focus on static analysis. JanuSec detects malicious behavior AFTER package is installed.

2. **HopGraph Propagation Tracking**: Unique ability to visualize worm propagation across hosts.

3. **Cross-Domain Correlation**: Link supply chain attack to subsequent endpoint compromise to cloud access.

4. **LLM-Assisted Triage**: Automated analysis reducing analyst workload.

---

## Summary: Key Enhancements Over Previous Document

| Area | Previous Document | This Enhancement |
|------|-------------------|------------------|
| **Shai-Hulud Details** | Basic overview | Wave 1 + Wave 2 technical details, wiper behavior, Bun obfuscation |
| **GitHub Actions** | Mentioned | Full CVE-2025-30066 analysis, double-base64, tag manipulation |
| **XZ Utils** | Correct but brief | Social engineering timeline, benevolent stranger pattern |
| **Pipeline Integration** | Conceptual | Complete 21-step mapping with code |
| **HopGraph Schema** | Mentioned | Full node/edge definitions + queries |
| **Binary Analysis** | Mentioned | Package payload analyzer implementation |
| **LLM Prompts** | Basic | Production-ready Tier 1/Tier 2 prompts |
| **YARA Rules** | None | Shai-Hulud, GitHub Actions, Crypto Hijack rules |
| **Correlation Rules** | Basic | Complete YAML rule set |
| **Gap Analysis** | Incomplete | Prioritized roadmap with effort estimates |

---

## References

### Primary Sources (Verified)
- [Unit 42: Shai-Hulud Worm Analysis](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- [Wiz: Shai-Hulud Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)
- [CISA: NPM Ecosystem Compromise Alert](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)
- [Unit 42: GitHub Actions Supply Chain Attack](https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/)
- [CISA: tj-actions/reviewdog CVE-2025-30066](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction)
- [OpenSSF: Securing CI/CD Pipelines](https://openssf.org/blog/2025/06/11/maintainers-guide-securing-ci-cd-pipelines-after-the-tj-actions-and-reviewdog-supply-chain-attacks/)
- [JFrog: XZ Backdoor CVE-2024-3094](https://jfrog.com/blog/xz-backdoor-attack-cve-2024-3094-all-you-need-to-know/)
- [Datadog: GuardDog Malicious Package Detection](https://securitylabs.datadoghq.com/articles/guarddog-identify-malicious-pypi-packages/)

---

**Document Version:** 2.0
**Last Updated:** 2025-11-30
**Owner:** Security Research Team
**Next Review:** 2025-12-15
