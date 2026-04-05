# JanuSec Pipeline Calibration Fix Guide
## Why Everything Looks Suspicious (And How to Fix It)

**Version:** 1.0  
**Date:** November 2025  
**Purpose:** Diagnose and fix the false positive epidemic in the 21-stage pipeline

---

## Executive Summary

Your pipeline has a **mathematical design flaw**: it only adds, never subtracts. Combined with sparse telemetry from Cyberstash XDR, this creates a perfect storm where:

- 135/500 rows (27%) flagged as SUSPICIOUS
- DREAD scores of 8-9 on single-factor detections
- Same `novel_global` signal repeated across nearly every alert
- Analysts ignoring all output because it's indistinguishable noise

**The core problems (anchored to code + inputs):**

| Problem | Impact | Root Cause |
|---------|--------|------------|
| Additive-only scoring | Everything trends toward SUSPICIOUS | _blend() in src/core/event_pipeline/pipeline.py always adds incoming deltas. |
| No trust signal subtraction | Verified Good still shows DREAD 9 | AllowlistManager.apply appends tags but never subtracts; certificate stage lacks negative confidence paths. |
| 
ovel_global floods detections | 80%+ of rows get this factor | 
are_token_stage in stages/network.py emits it whenever hashes aren?t in the baseline (most Cyberstash hashes). |
| Missing data = neutral | Low confidence but high severity | Cyberstash CSV importer (src/api/csv_handler.py) drops host/user/signer/parent fields, so scoring treats gaps as "no evidence against". |
| Synthetic MITRE mapping | False expertise displayed | /api/v1/risk/{id}/explain falls back to client-synth when event_id missing, yet the UI still renders techniques. |
| No tier gating | Everything floods Tier 1 | Pipeline output lacks 	ier metadata and rontend/static/csv_analyzer.html renders every row regardless of confidence. |

> **Telemetry reality check:** Until the Cyberstash adapter maps vendor-specific columns (device hostname, userPrincipalName, signer) the math must assume high uncertainty instead of claiming "targeted malware".


---

## Part 1: The Mathematical Problem

### Current Scoring Model (Broken)

Based on the pipeline review, your current `_blend()` function works like this:

```python
# CURRENT (BROKEN) - Pseudocode
def _blend(current_confidence, incoming_delta, factors):
    # Always adds, never subtracts
    new_confidence = current_confidence + (incoming_delta * weight)
    factors.append(new_factor)
    return max(0, min(100, new_confidence))  # Clamp 0-100
```

**Why this fails:**

```
Event: fsagentcrashstatusupdater.exe

Stage 1 (baseline):     confidence = 0 + 15 = 15  (avPositives > 0)
Stage 4 (endpoint):     confidence = 15 + 20 = 35 (temp_dropper_path)
Stage 18 (rare_token):  confidence = 35 + 25 = 60 (novel_global)
Stage 19 (hunt_lanes):  confidence = 60 + 0 = 60  (no match, but no subtraction)

Trust signals present:
- flagName = "Verified Good" → NO EFFECT (doesn't subtract)
- Signature = valid vendor → NO EFFECT (doesn't subtract)

Final: confidence = 60%, verdict = SUSPICIOUS
```

The math is **monotonically increasing**. Once a factor adds confidence, nothing removes it.

### DREAD Score Problem

Your DREAD calculation appears to be:

```python
# CURRENT DREAD (INFERRED)
dread = (damage + reproducibility + exploitability + affected_users + discoverability) / 5

# Where each component defaults HIGH when data is missing
damage = 8          # Default high because "unknown impact"
reproducibility = 7 # Default medium-high
exploitability = 9  # Default high because "novel" = "unknown defense"
affected_users = 6  # Default medium (unknown scope)
discoverability = 9 # Default high because "we detected it"

DREAD = (8 + 7 + 9 + 6 + 9) / 5 = 7.8 → rounds to 8
```

**The flaw:** Missing data defaults to HIGH values. This is backwards—missing data should default to UNCERTAIN, which means lower severity until proven otherwise.

---

## Part 2: The Correct Scoring Model

### Principle: Bayesian-Inspired Confidence

We should model confidence as a probability that updates both UP and DOWN based on evidence:

```
P(malicious | evidence) = P(evidence | malicious) × P(malicious) / P(evidence)
```

In practical terms:

- **Positive evidence** (suspicious behavior) → increases confidence
- **Negative evidence** (trust signals) → decreases confidence
- **Missing evidence** → increases uncertainty, which should CAP severity

### New Confidence Calculation

```python
# FIXED SCORING MODEL

class ConfidenceCalculator:
    def __init__(self):
        self.base_confidence = 0.0
        self.positive_factors = []
        self.negative_factors = []
        self.uncertainty_penalty = 0.0
    
    def add_positive_factor(self, factor_name: str, weight: float, evidence_quality: float):
        """
        Add a factor that increases suspicion.
        
        weight: Base impact (0.0 - 1.0)
        evidence_quality: How reliable is this evidence? (0.0 - 1.0)
            - 1.0 = Direct observation (saw C2 callback)
            - 0.7 = Strong inference (known malware hash)
            - 0.4 = Weak inference (novel hash, no behavior)
            - 0.1 = Synthetic/placeholder
        """
        effective_weight = weight * evidence_quality
        self.positive_factors.append({
            'name': factor_name,
            'weight': weight,
            'evidence_quality': evidence_quality,
            'effective_weight': effective_weight
        })
        self.base_confidence += effective_weight
    
    def add_negative_factor(self, factor_name: str, weight: float, trust_quality: float):
        """
        Add a factor that DECREASES suspicion.
        
        weight: Base impact (0.0 - 1.0)
        trust_quality: How reliable is this trust signal? (0.0 - 1.0)
            - 1.0 = Analyst verified + no contradicting evidence
            - 0.8 = Valid vendor signature
            - 0.5 = On allowlist but not manually verified
            - 0.3 = Low AV consensus (< 5/70 detections)
        """
        effective_weight = weight * trust_quality
        self.negative_factors.append({
            'name': factor_name,
            'weight': weight,
            'trust_quality': trust_quality,
            'effective_weight': effective_weight
        })
        self.base_confidence -= effective_weight
    
    def add_uncertainty(self, missing_field: str, importance: float):
        """
        Missing critical data increases uncertainty, which CAPS severity.
        
        importance: How much does this missing data matter?
            - host/user missing: 0.3 (can't assess blast radius)
            - signer missing: 0.2 (can't verify trust)
            - parent process missing: 0.25 (can't assess attack vector)
            - network telemetry missing: 0.2 (can't confirm C2)
        """
        self.uncertainty_penalty += importance
    
    def calculate_final_confidence(self) -> dict:
        """
        Calculate final confidence with uncertainty adjustment.
        
        Formula:
        raw_confidence = sum(positive) - sum(negative)
        uncertainty_cap = 1.0 - uncertainty_penalty
        final_confidence = min(raw_confidence, uncertainty_cap)
        """
        raw_confidence = self.base_confidence
        
        # Clamp to 0-1 range
        raw_confidence = max(0.0, min(1.0, raw_confidence))
        
        # Apply uncertainty cap
        # High uncertainty means we CAN'T be highly confident it's malicious
        uncertainty_cap = max(0.3, 1.0 - self.uncertainty_penalty)
        
        final_confidence = min(raw_confidence, uncertainty_cap)
        
        return {
            'raw_confidence': raw_confidence,
            'uncertainty_penalty': self.uncertainty_penalty,
            'uncertainty_cap': uncertainty_cap,
            'final_confidence': final_confidence,
            'confidence_percent': int(final_confidence * 100),
            'positive_factors': self.positive_factors,
            'negative_factors': self.negative_factors,
            'verdict': self._determine_verdict(final_confidence)
        }
    
    def _determine_verdict(self, confidence: float) -> str:
        if confidence >= 0.85:
            return "MALICIOUS"
        elif confidence >= 0.65:
            return "LIKELY_MALICIOUS"
        elif confidence >= 0.45:
            return "SUSPICIOUS"
        elif confidence >= 0.25:
            return "NEEDS_INVESTIGATION"
        else:
            return "LIKELY_BENIGN"
```

**How this wires into the existing pipeline:** stash a `ConfidenceCalculator` inside `StageContext.state`. Each stage pushes `{'factor': name, 'delta': weight, 'type': 'positive|negative'}` instead of writing directly to `_blend()`. After the `for stage in STAGE_DEFINITIONS` loop (see `src/core/event_pipeline/pipeline.py:147`), call `calculator.calculate_final_confidence()` to get the final verdict. This keeps stage runners unchanged while letting us log which stage contributed each factor.

### Example: Same Event with Fixed Scoring

```python
# fsagentcrashstatusupdater.exe with FIXED scoring

calc = ConfidenceCalculator()

# Positive factors (what makes it suspicious)
calc.add_positive_factor(
    'novel_global', 
    weight=0.15,           # Reduced from 0.25 - novelty alone is weak signal
    evidence_quality=0.4   # Weak inference - no behavioral evidence
)
calc.add_positive_factor(
    'temp_dropper_path',
    weight=0.20,
    evidence_quality=0.6   # Medium - legitimate software also uses temp
)
calc.add_positive_factor(
    'av_positives_low',    # 4/74 detections
    weight=0.10,
    evidence_quality=0.3   # Low consensus = low quality signal
)

# Negative factors (what makes it less suspicious)
calc.add_negative_factor(
    'verified_good_flag',
    weight=0.40,           # Analyst override is strong
    trust_quality=0.9      # High trust if no contradicting evidence
)
calc.add_negative_factor(
    'vendor_signature_valid',  # If present
    weight=0.30,
    trust_quality=0.8
)

# Uncertainty (missing data)
calc.add_uncertainty('host_unknown', importance=0.25)
calc.add_uncertainty('user_unknown', importance=0.20)
calc.add_uncertainty('parent_process_unknown', importance=0.25)
calc.add_uncertainty('network_telemetry_missing', importance=0.15)

result = calc.calculate_final_confidence()

# OUTPUT:
# raw_confidence: 0.15*0.4 + 0.20*0.6 + 0.10*0.3 - 0.40*0.9 - 0.30*0.8
#               = 0.06 + 0.12 + 0.03 - 0.36 - 0.24
#               = -0.39 → clamped to 0.0
# uncertainty_penalty: 0.25 + 0.20 + 0.25 + 0.15 = 0.85
# uncertainty_cap: 1.0 - 0.85 = 0.15 (max 15% confidence allowed)
# final_confidence: min(0.0, 0.15) = 0.0
# verdict: LIKELY_BENIGN

# Compare to current broken output:
# CURRENT: confidence=60%, verdict=SUSPICIOUS, DREAD=9
# FIXED:   confidence=0%, verdict=LIKELY_BENIGN, DREAD=2
```

---

## Part 3: Fixed DREAD Calculation

### Current Problem

Your DREAD defaults missing data to HIGH. This is wrong because:

- Unknown ≠ High risk
- Unknown = Uncertain risk = Lower confidence in severity

### Fixed DREAD Model (drop-in for `artifact/risk.py`)

```python
class DREADCalculator:
    """
    DREAD with uncertainty-aware defaults.
    
    Key change: Missing data defaults to MEDIUM (5) not HIGH (8-9).
    Additional change: Evidence quality weights each component.
    """
    
    def __init__(self):
        self.components = {
            'damage': {'value': 5, 'evidence_quality': 0.0, 'source': 'default'},
            'reproducibility': {'value': 5, 'evidence_quality': 0.0, 'source': 'default'},
            'exploitability': {'value': 5, 'evidence_quality': 0.0, 'source': 'default'},
            'affected_users': {'value': 5, 'evidence_quality': 0.0, 'source': 'default'},
            'discoverability': {'value': 5, 'evidence_quality': 0.0, 'source': 'default'}
        }
    
    def set_damage(self, value: int, evidence: str, quality: float):
        """
        Damage potential (1-10).
        
        Evidence types and suggested values:
        - Ransomware confirmed: 10, quality=1.0
        - Data exfiltration observed: 9, quality=0.9
        - Credential access attempted: 8, quality=0.8
        - Persistence established: 7, quality=0.7
        - Unknown executable: 5, quality=0.3 (default, uncertain)
        - Monitoring tool: 2, quality=0.8
        """
        self.components['damage'] = {
            'value': value,
            'evidence_quality': quality,
            'source': evidence
        }
    
    def set_reproducibility(self, value: int, evidence: str, quality: float):
        """
        How easily can this be reproduced? (1-10)
        
        - Automated exploit: 10, quality=0.9
        - Known CVE with POC: 8, quality=0.8
        - Requires user interaction: 5, quality=0.7
        - Targeted/manual attack: 3, quality=0.6
        - Unknown: 5, quality=0.2
        """
        self.components['reproducibility'] = {
            'value': value,
            'evidence_quality': quality,
            'source': evidence
        }
    
    def set_exploitability(self, value: int, evidence: str, quality: float):
        """
        How easy to exploit? (1-10)
        
        - Public exploit available: 10, quality=0.9
        - LOLBin abuse: 8, quality=0.8
        - Requires local access: 5, quality=0.7
        - Requires admin: 3, quality=0.7
        - Unknown technique: 5, quality=0.2
        """
        self.components['exploitability'] = {
            'value': value,
            'evidence_quality': quality,
            'source': evidence
        }
    
    def set_affected_users(self, value: int, evidence: str, quality: float):
        """
        Scope of impact (1-10).
        
        - Domain admin compromised: 10, quality=0.9
        - Multiple hosts confirmed: 8, quality=0.8
        - Single privileged user: 6, quality=0.7
        - Single standard user: 4, quality=0.7
        - Unknown user/host: 5, quality=0.2 (uncertain scope)
        """
        self.components['affected_users'] = {
            'value': value,
            'evidence_quality': quality,
            'source': evidence
        }
    
    def set_discoverability(self, value: int, evidence: str, quality: float):
        """
        How easy to discover? (1-10)
        
        Note: This is often misused. High discoverability means
        attacker can easily find the vulnerability, NOT that we detected it.
        
        - Public-facing service: 9, quality=0.8
        - Internal service: 5, quality=0.7
        - Requires insider knowledge: 3, quality=0.6
        - Unknown attack surface: 5, quality=0.2
        """
        self.components['discoverability'] = {
            'value': value,
            'evidence_quality': quality,
            'source': evidence
        }
    
    def calculate(self) -> dict:
        """
        Calculate DREAD with evidence-weighted averaging.
        
        Formula:
        weighted_sum = Σ(value × evidence_quality)
        total_weight = Σ(evidence_quality)
        
        If total_weight < 1.0, we have high uncertainty,
        so we pull the score toward the neutral midpoint (5).
        """
        weighted_sum = 0
        total_quality = 0
        
        for component, data in self.components.items():
            weighted_sum += data['value'] * data['evidence_quality']
            total_quality += data['evidence_quality']
        
        if total_quality == 0:
            # No evidence at all - return neutral with high uncertainty
            return {
                'score': 5,
                'uncertainty': 'HIGH',
                'components': self.components,
                'recommendation': 'NEEDS_ENRICHMENT'
            }
        
        # Evidence-weighted average
        evidence_score = weighted_sum / total_quality
        
        # Uncertainty adjustment: pull toward neutral (5) based on missing evidence
        # max_quality = 5.0 (if all 5 components have quality=1.0)
        uncertainty_factor = total_quality / 5.0
        
        # Blend between evidence score and neutral based on certainty
        final_score = (evidence_score * uncertainty_factor) + (5 * (1 - uncertainty_factor))
        
        # Determine uncertainty band
        if uncertainty_factor >= 0.8:
            uncertainty_band = 'LOW'
        elif uncertainty_factor >= 0.5:
            uncertainty_band = 'MEDIUM'
        else:
            uncertainty_band = 'HIGH'
        
        return {
            'score': round(final_score, 1),
            'score_int': int(round(final_score)),
            'evidence_score': round(evidence_score, 1),
            'uncertainty': uncertainty_band,
            'uncertainty_factor': round(uncertainty_factor, 2),
            'components': self.components,
            'recommendation': self._get_recommendation(final_score, uncertainty_band)
        }
    
    def _get_recommendation(self, score: float, uncertainty: str) -> str:
        if uncertainty == 'HIGH':
            return 'NEEDS_ENRICHMENT'
        elif score >= 8:
            return 'IMMEDIATE_ACTION'
        elif score >= 6:
            return 'INVESTIGATE_PRIORITY'
        elif score >= 4:
            return 'INVESTIGATE_NORMAL'
        else:
            return 'MONITOR'
```

When integrating, call the new calculator from `src/artifact/risk.py` (currently computing DREAD inline) so UI and reports automatically pick up the improved score plus `uncertainty` field.

### Example: Same Event with Fixed DREAD

```python
# fsagentcrashstatusupdater.exe with FIXED DREAD

dread = DREADCalculator()

# We only know: novel hash + temp path + low AV hits
# We DON'T know: actual behavior, scope, user, technique

dread.set_damage(
    value=5,                    # Unknown = neutral
    evidence='no_behavioral_telemetry',
    quality=0.2                 # Low quality - we're guessing
)

dread.set_reproducibility(
    value=5,                    # Unknown
    evidence='no_execution_context',
    quality=0.1
)

dread.set_exploitability(
    value=6,                    # Slightly elevated - temp execution is easy
    evidence='temp_path_execution',
    quality=0.4                 # Medium-low - this is circumstantial
)

dread.set_affected_users(
    value=5,                    # Unknown
    evidence='host_user_unknown',
    quality=0.1
)

dread.set_discoverability(
    value=5,                    # Unknown attack surface
    evidence='no_network_context',
    quality=0.1
)

result = dread.calculate()

# OUTPUT:
# weighted_sum = 5*0.2 + 5*0.1 + 6*0.4 + 5*0.1 + 5*0.1 = 1.0 + 0.5 + 2.4 + 0.5 + 0.5 = 4.9
# total_quality = 0.2 + 0.1 + 0.4 + 0.1 + 0.1 = 0.9
# evidence_score = 4.9 / 0.9 = 5.44
# uncertainty_factor = 0.9 / 5.0 = 0.18
# final_score = (5.44 * 0.18) + (5 * 0.82) = 0.98 + 4.1 = 5.08
# 
# Result:
# score: 5.1 (rounded to 5)
# uncertainty: HIGH
# recommendation: NEEDS_ENRICHMENT

# Compare to current:
# CURRENT: DREAD = 9
# FIXED:   DREAD = 5 with "NEEDS_ENRICHMENT" label
```

---

## Part 4: Factor Weight Calibration

### Current Factor Weights (Inferred)

Based on the pipeline review, your current weights appear to be:

| Factor | Current Weight | Problem |
|--------|---------------|---------|
| `novel_global` | +25% | Way too high for a single-factor detection |
| `temp_dropper_path` | +20% | Reasonable, but needs context |
| `unsigned_sensitive_path` | +20% | Should check if path actually matters |
| `lane_process_lineage:*` | +15% | Good signal, appropriate weight |
| `threatWeight` (AV) | +7-15% | Scaled by consensus, OK |
| `identity_unknown` | 0% | Should be uncertainty, not neutral |
| `cert_unknown` | 0% | Should be uncertainty, not neutral |
| `verified_good` | 0% | **CRITICAL BUG** - should be -40% |
| `allowlist_hit` | 0% | **CRITICAL BUG** - should be -30% |

### Fixed Factor Weights

```python
# FACTOR WEIGHT CONFIGURATION

POSITIVE_FACTORS = {
    # High confidence signals (behavioral evidence)
    'c2_callback_observed': {'base_weight': 0.45, 'min_quality': 0.8},
    'credential_theft_attempted': {'base_weight': 0.40, 'min_quality': 0.7},
    'ransomware_behavior': {'base_weight': 0.50, 'min_quality': 0.9},
    'lateral_movement_observed': {'base_weight': 0.40, 'min_quality': 0.8},
    
    # Medium confidence signals (strong circumstantial)
    'lane_process_lineage_suspicious': {'base_weight': 0.25, 'min_quality': 0.6},
    'beacon_pattern_detected': {'base_weight': 0.30, 'min_quality': 0.6},
    'known_malware_hash': {'base_weight': 0.35, 'min_quality': 0.8},
    'lolbin_abuse': {'base_weight': 0.25, 'min_quality': 0.6},
    
    # Low confidence signals (weak circumstantial)
    'novel_global': {'base_weight': 0.10, 'min_quality': 0.3},  # REDUCED from 0.25
    'temp_dropper_path': {'base_weight': 0.12, 'min_quality': 0.4},  # REDUCED
    'unsigned_sensitive_path': {'base_weight': 0.10, 'min_quality': 0.4},
    'av_positives_low': {'base_weight': 0.08, 'min_quality': 0.2},  # <10/70 detections
    'av_positives_medium': {'base_weight': 0.20, 'min_quality': 0.5},  # 10-30/70
    'av_positives_high': {'base_weight': 0.35, 'min_quality': 0.8},  # >30/70
    
    # Contextual signals (need corroboration)
    'asn_rarity_high': {'base_weight': 0.15, 'min_quality': 0.4},
    'domain_novelty_high': {'base_weight': 0.12, 'min_quality': 0.3},
}

NEGATIVE_FACTORS = {
    # Strong trust signals
    'analyst_verified_good': {'base_weight': -0.45, 'min_quality': 0.9},
    'allowlist_hit_verified': {'base_weight': -0.35, 'min_quality': 0.8},
    'valid_vendor_signature': {'base_weight': -0.30, 'min_quality': 0.7},
    'known_good_hash': {'base_weight': -0.35, 'min_quality': 0.8},
    
    # Medium trust signals
    'allowlist_hit_unverified': {'base_weight': -0.20, 'min_quality': 0.5},
    'trusted_publisher': {'base_weight': -0.20, 'min_quality': 0.6},
    'enterprise_baseline_match': {'base_weight': -0.15, 'min_quality': 0.5},
    
    # Weak trust signals
    'av_clean': {'base_weight': -0.10, 'min_quality': 0.4},  # 0/70 detections
    'common_software_name': {'base_weight': -0.05, 'min_quality': 0.3},
}

UNCERTAINTY_PENALTIES = {
    # Missing context that limits our confidence
    'host_unknown': 0.20,
    'user_unknown': 0.15,
    'parent_process_unknown': 0.20,
    'signer_unknown': 0.15,
    'network_telemetry_missing': 0.15,
    'no_behavioral_evidence': 0.25,
    'single_factor_only': 0.20,  # NEW: penalize single-factor detections
}
```

### Why These Weights?

**Principle 1: Behavioral > Circumstantial > Novelty**

```
Evidence Hierarchy (most to least reliable):

1. OBSERVED BEHAVIOR (0.35-0.50 weight)
   - C2 callback, ransomware encryption, credential dump
   - These are direct observations of malicious activity
   - High confidence because we saw it happen

2. STRONG CIRCUMSTANTIAL (0.20-0.35 weight)
   - Known malware hash, suspicious process chain, beacon pattern
   - Not direct observation, but strong inference
   - Medium-high confidence

3. WEAK CIRCUMSTANTIAL (0.08-0.15 weight)
   - Novel hash, temp path execution, unsigned binary
   - Could be malicious OR legitimate
   - Low confidence alone, needs corroboration

4. CONTEXTUAL ONLY (0.05-0.10 weight)
   - Rare ASN, new domain, unusual timing
   - Interesting but not indicative alone
   - Very low confidence, noise if used alone
```

**Principle 2: Trust Signals Must Subtract**

```
If confidence only goes UP, you get:
  novel + temp + unsigned = 55% → SUSPICIOUS

If trust signals SUBTRACT, you get:
  novel + temp + unsigned - verified_good - valid_sig = -10% → LIKELY_BENIGN

This is mathematically necessary for the system to ever conclude "not malicious."
```

**Principle 3: Uncertainty Caps Confidence**

```
Missing data should NOT default to high risk.
Missing data should LIMIT how confident we can be.

With host/user/signer all unknown:
  uncertainty_penalty = 0.20 + 0.15 + 0.15 = 0.50
  uncertainty_cap = 1.0 - 0.50 = 0.50 (max 50% confidence)

This means: "We can't be more than 50% sure it's malicious
because we're missing 50% of the context we need."
```

---

## Part 5: Tier Gating Logic

### Current Problem

Everything goes to Tier 1. No filtering. Result: 135/500 rows in the queue.

### Fixed Tier Routing

```python
class TierRouter:
    """
    Route alerts to appropriate tier based on confidence and evidence quality.
    """
    
    @staticmethod
    def determine_tier(confidence_result: dict, dread_result: dict) -> dict:
        confidence = confidence_result['final_confidence']
        uncertainty = dread_result['uncertainty']
        positive_factors = len(confidence_result['positive_factors'])
        negative_factors = len(confidence_result['negative_factors'])
        
        # TIER 1: Immediate analyst attention
        # Requires: High confidence OR high DREAD with medium+ confidence
        if confidence >= 0.65 and uncertainty != 'HIGH':
            return {
                'tier': 1,
                'queue': 'immediate',
                'reason': 'High confidence malicious activity',
                'sla_hours': 1
            }
        
        if dread_result['score'] >= 7 and confidence >= 0.45 and uncertainty != 'HIGH':
            return {
                'tier': 1,
                'queue': 'priority',
                'reason': 'High severity with supporting evidence',
                'sla_hours': 4
            }
        
        # TIER 2 AUTO: Needs deeper investigation but not urgent
        # Moderate confidence, or high confidence but high uncertainty
        if confidence >= 0.35 and positive_factors >= 2:
            return {
                'tier': 2,
                'queue': 'investigate',
                'reason': 'Multiple suspicious factors require analysis',
                'sla_hours': 24
            }
        
        # NEEDS ENRICHMENT: Missing too much data to assess
        if uncertainty == 'HIGH' or confidence_result['uncertainty_penalty'] >= 0.5:
            return {
                'tier': 0,
                'queue': 'enrich',
                'reason': 'Insufficient telemetry for assessment',
                'sla_hours': None,
                'enrichment_needed': [
                    f for f in ['host', 'user', 'parent', 'signer', 'network']
                    if f + '_unknown' in str(confidence_result)
                ]
            }
        
        # MONITOR: Single weak factor, no corroboration
        if positive_factors == 1 and confidence < 0.35:
            return {
                'tier': 0,
                'queue': 'monitor',
                'reason': 'Single weak signal, no corroborating evidence',
                'sla_hours': None,
                'auto_close_hours': 168  # Auto-close after 7 days if no new signals
            }
        
        # LIKELY BENIGN: Trust signals outweigh suspicion
        if confidence <= 0.15 or negative_factors >= 2:
            return {
                'tier': 0,
                'queue': 'benign',
                'reason': 'Trust signals indicate likely legitimate',
                'sla_hours': None,
                'auto_close_hours': 24
            }
        
        # DEFAULT: Low priority investigation
        return {
            'tier': 2,
            'queue': 'backlog',
            'reason': 'Low confidence, requires manual review',
            'sla_hours': 72
        }
```

### Expected Impact

With fixed scoring + tier routing:

```
BEFORE (current):
  Tier 1 queue: 135 rows (27% of 500)
  All showing SUSPICIOUS with DREAD 8-9
  Analysts overwhelmed, ignoring alerts

AFTER (fixed):
  Tier 1 immediate: ~5-10 rows (1-2%)    - Actual threats
  Tier 1 priority: ~10-15 rows (2-3%)    - High severity, needs review
  Tier 2 investigate: ~20-30 rows (4-6%) - Multiple factors, dig deeper
  Enrich queue: ~50-70 rows (10-14%)     - Need more data
  Monitor queue: ~80-100 rows (16-20%)   - Single factor, watch
  Benign/closed: ~275-335 rows (55-67%)  - Trust signals, close
```

---

## Part 6: MITRE Mapping Fix

### Current Problem

MITRE techniques assigned even when no supporting telemetry:

```json
{
  "mitre_techniques": ["T1059.003", "T1105", "T1055"],
  "source": "client-synth"  // This means SYNTHETIC - not real evidence!
}
```

### Fixed MITRE Mapping

```python
class MITREMapper:
    """
    Only map MITRE techniques when we have supporting evidence.
    """
    
    TECHNIQUE_REQUIREMENTS = {
        'T1059.001': {  # PowerShell
            'required_evidence': ['powershell_execution', 'encoded_command'],
            'confidence_threshold': 0.6
        },
        'T1059.003': {  # Windows Command Shell
            'required_evidence': ['cmd_execution', 'suspicious_command_line'],
            'confidence_threshold': 0.5
        },
        'T1055': {  # Process Injection
            'required_evidence': ['memory_injection_detected', 'hollowing_detected'],
            'confidence_threshold': 0.7
        },
        'T1105': {  # Ingress Tool Transfer
            'required_evidence': ['download_observed', 'network_artifact'],
            'confidence_threshold': 0.6
        },
        'T1036': {  # Masquerading
            'required_evidence': ['name_mismatch', 'path_anomaly'],
            'confidence_threshold': 0.5
        }
    }
    
    @classmethod
    def map_techniques(cls, factors: list, evidence: list) -> list:
        """
        Map MITRE techniques only when evidence supports them.
        """
        mapped = []
        
        for technique_id, requirements in cls.TECHNIQUE_REQUIREMENTS.items():
            # Check if we have the required evidence
            has_evidence = any(
                e in [f['name'] for f in factors] or e in evidence
                for e in requirements['required_evidence']
            )
            
            if has_evidence:
                # Calculate confidence in this technique
                matching_factors = [
                    f for f in factors 
                    if f['name'] in requirements['required_evidence']
                ]
                avg_confidence = sum(f['effective_weight'] for f in matching_factors) / len(matching_factors) if matching_factors else 0
                
                if avg_confidence >= requirements['confidence_threshold']:
                    mapped.append({
                        'technique_id': technique_id,
                        'confidence': 'HIGH',
                        'evidence': [f['name'] for f in matching_factors],
                        'source': 'telemetry'
                    })
                else:
                    mapped.append({
                        'technique_id': technique_id,
                        'confidence': 'LOW',
                        'evidence': [f['name'] for f in matching_factors],
                        'source': 'inference'
                    })
        
        return mapped
    
    @classmethod
    def get_placeholder_warning(cls, synthetic_techniques: list) -> str:
        """
        When techniques are synthetic, return a clear warning.
        """
        if not synthetic_techniques:
            return None
        
        return (
            f"⚠️ MITRE techniques {', '.join(synthetic_techniques)} are SUGGESTED "
            f"based on artifact type, not observed behavior. "
            f"Collect behavioral telemetry to confirm."
        )
``
> **Tier-2 LLM impact:** Once Tier-1 marks a record Needs enrichment, /api/v1/csv/tier2_investigate should echo that state and surface the MITRE warning instead of inventing confidence.

`

---

## Part 7: Implementation Checklist

### Phase 1: Critical Math Fixes (Week 1)

- 1. Modify _blend() to support negative weights (src/core/event_pipeline/pipeline.py).
- 2. Add uncertainty tracking + cap calculation (pipeline.py).
- 3. Introduce ConfidenceCalculator helper (new src/core/event_pipeline/scoring.py) and stash it in StageContext.
- 4. Move DREAD math into src/core/event_pipeline/dread.py using the uncertainty-aware calculator.
- 5. Reduce 
ovel_global base weight from 0.25 to 0.10 in stages/network.py.
- 6. Patch Cyberstash CSV ingestion (src/api/csv_handler.py) to map device hostname, user, signer, and parent fields so the new scoring gets real context.

### Phase 2: Trust Signal Integration (Week 2)

- 7. Emit negative factors for allowlist hits (stages/primitives.py).
- 8. Emit negative factors for valid signatures (certificate stage wrapper).
- 9. Respect analyst overrides from CSV (lagName == "Verified Good").
- 10. Ensure trust factors are applied after positive factors in pipeline.py.

### Phase 3: Tier Routing (Week 3)

- 11. Implement TierRouter (new src/core/event_pipeline/routing.py) and attach tier metadata to PipelineResult.
- 12. Update csv_analyzer.html to filter rows by tier and display queue labels.
- 13. Add a "Needs Enrichment" card for rows capped by uncertainty.

### Phase 4: MITRE & UI Fixes (Week 4)

- 14. Fix synthetic MITRE mapping by using the evidence-aware mapper in the explain endpoint.
- 15. Surface positive vs negative factors in Tier?1 UI.
- 16. Show uncertainty + missing telemetry in Tier?2 UI, and add a "Request Enrichment" workflow button.


---

## Part 8: Validation Metrics

### Before/After Comparison
Run the same 500-row Cyberstash CSV we keep under `tests/test_data/cyberstash_sample.csv` (used by `tests/test_csv_analyzer_perf.py`) through both systems so we can compare apples to apples:

| Metric | Current (Broken) | Target (Fixed) |
|--------|-----------------|----------------|
| Rows flagged SUSPICIOUS | 135 (27%) | <25 (5%) |
| Rows flagged MALICIOUS | 0 | Only with behavioral evidence |
| Rows in Tier 1 queue | 135 | <30 |
| Rows needing enrichment | 0 (shown) | ~70 (explicitly labeled) |
| Average DREAD score | 7.8 | 4.5-5.5 |
| Rows with valid negative factors | 0 | 40+ (allowlist, signatures) |
| Single-factor detections in Tier 1 | 120+ | 0 |

### Trust Calibration Test

For rows where analysts previously marked "Verified Good":

| Metric | Current | Target |
|--------|---------|--------|
| Still showing SUSPICIOUS | 100% | 0% |
| DREAD score | 8-9 | 2-3 |
| In Tier 1 queue | Yes | No (closed or monitor) |

---

## Part 9: Quick Reference - The Math

### Confidence Formula

```
raw_confidence = Σ(positive_weight × evidence_quality) - Σ(negative_weight × trust_quality)

uncertainty_cap = 1.0 - Σ(missing_field_importance)

final_confidence = min(raw_confidence, uncertainty_cap)

verdict = 
  MALICIOUS if final_confidence ≥ 0.85
  LIKELY_MALICIOUS if final_confidence ≥ 0.65
  SUSPICIOUS if final_confidence ≥ 0.45
  NEEDS_INVESTIGATION if final_confidence ≥ 0.25
  LIKELY_BENIGN otherwise
```

### DREAD Formula

```
For each component (D, R, E, A, D):
  weighted_value = component_value × evidence_quality

evidence_score = Σ(weighted_value) / Σ(evidence_quality)

uncertainty_factor = Σ(evidence_quality) / 5.0

final_dread = (evidence_score × uncertainty_factor) + (5 × (1 - uncertainty_factor))
```

### Tier Routing Logic

```
IF confidence ≥ 0.65 AND uncertainty ≠ HIGH:
  → Tier 1 Immediate

IF dread ≥ 7 AND confidence ≥ 0.45 AND uncertainty ≠ HIGH:
  → Tier 1 Priority

IF confidence ≥ 0.35 AND factors ≥ 2:
  → Tier 2 Investigate

IF uncertainty = HIGH OR missing_data ≥ 50%:
  → Enrich Queue

IF factors = 1 AND confidence < 0.35:
  → Monitor Queue

IF confidence ≤ 0.15 OR trust_factors ≥ 2:
  → Likely Benign (auto-close)
```

---

## Part 10: Why This Math Works

### The Bayesian Intuition

Think of confidence as "probability this is malicious given the evidence."

**Current system:**
- Every piece of evidence adds probability
- Nothing subtracts
- Result: P(malicious) trends toward 100%

**Fixed system:**
- Suspicious evidence adds probability
- Trust evidence subtracts probability  
- Missing evidence caps maximum probability
- Result: P(malicious) reflects actual evidence balance

### The Insurance Analogy

Imagine you're an insurance adjuster assessing a car claim:

**Current system:**
- Car was in an accident → +30% fraud likelihood
- Driver has speeding tickets → +20%
- Car is expensive → +15%
- Result: 65% fraud likelihood, flag for investigation

**Problem:** You never check if the driver has a clean claims history, valid insurance, and witnesses confirming the accident.

**Fixed system:**
- Car was in an accident → +30%
- Driver has speeding tickets → +20%
- Car is expensive → +15%
- Clean claims history → -25%
- Multiple witnesses → -20%
- Police report matches → -15%
- Result: 5% fraud likelihood, approve claim

### The "Novel Hash" Problem

`novel_global` fires on ~80% of your rows because most hashes aren't in your baseline. This is not evidence of malice—it's evidence that your baseline is incomplete.

**Current logic:** "I've never seen this hash" → "It might be bad" → +25% confidence

**Fixed logic:** "I've never seen this hash" → "I don't know if it's bad" → +10% confidence, but also +20% uncertainty penalty

The uncertainty penalty is key: it says "I can't be confident it's malicious BECAUSE I don't have enough data to judge."

---

## Closing Summary

Your pipeline isn't detecting too many threats—it's **mathematically incapable of concluding anything is benign**. 

The fix is straightforward:
1. Add subtraction for trust signals
2. Cap confidence based on missing data
3. Reduce weight of single-factor novelty detections
4. Gate Tier 1 to multi-factor, high-confidence alerts only

This isn't about lowering security—it's about **accurate** security. A system that cries wolf 27% of the time gets ignored. A system that's right 95% of the time gets trusted.

The code changes are relatively small. The impact on analyst workflow will be massive.

---

*Document prepared for the JanuSec pipeline calibration sprint. Open questions for Opus 4.5 before the code freeze: confirm Cyberstash provides host/user/signer columns going forward, decide whether Tier‑2 auto-runs on “Needs enrichment” rows, and align on which regression tests (CSV sample + tier routing playwright) must pass before rollout.*
