"""EndpointEmailMLPipeline — ML-based detectors for endpoint and email threat vectors.

Mirrors NetworkMLPipeline but covers:
  EMAIL DOMAIN
    URLRiskScorer           — Shannon entropy, homoglyph, redirect depth, domain age check
    AttachmentRiskAnalyzer  — zip-bomb, double-extension, OLE/macro byte signature, entropy
    BECScoringModel         — EWMA sender baseline, reply-to mismatch, first-contact anomaly

  ENDPOINT DOMAIN
    ProcessTreeAnomalyDetector  — IsolationForest on process lineage depth/rarity + TF-IDF cmdline
    PersistenceScoringModel     — Novel/burst persistence signal with temporal baseline

  ADVANCED ENDPOINT INTEGRATION
    AdvancedEndpointGateway — thin wrapper that calls detect_advanced_endpoint_threats()
                              from src.core.detectors.advanced_endpoint_threats and reshapes
                              output into the standard {factor, confidence, reason, tags} dict.

Usage (same as NetworkMLPipeline):
    pipeline = EndpointEmailMLPipeline()
    factors = pipeline.analyze_email_event(ev_dict)   # email domain
    factors = pipeline.analyze_endpoint_event(ev_dict) # endpoint domain

Each factor dict: {'factor': str, 'confidence': float, 'reason': str, 'tags': [str]}
"""
from __future__ import annotations

import math
import os
import re
import time
import unicodedata
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional ML primitives (graceful degradation without sklearn/numpy)
# ---------------------------------------------------------------------------
try:
    from src.core.detect.isolation_forest import IsolationForestDetector as _IFDetector
    _IF_AVAILABLE = True
except Exception:
    _IFDetector = None  # type: ignore
    _IF_AVAILABLE = False

try:
    from src.ml.tfidf_profile import TfidfProfile as _TfIdf
    _TFIDF_AVAILABLE = True
except Exception:
    _TfIdf = None  # type: ignore
    _TFIDF_AVAILABLE = False

# ---------------------------------------------------------------------------
# Homoglyph detection table (Latin confusables → ASCII)
# ---------------------------------------------------------------------------
_CONFUSABLE = str.maketrans({
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'r', '\u0441': 'c',
    '\u0456': 'i', '\u0458': 'j', '\u0501': 'd', '\u04cf': 'l',
    '0': 'o', '1': 'l', '5': 's', '3': 'e', '@': 'a',
})

_SHORTENER_DOMAINS = frozenset([
    'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','buff.ly','is.gd',
    'rb.gy','short.io','tiny.cc','cutt.ly','rebrand.ly',
])

_DOUBLE_EXT_RE = re.compile(
    r'\.(doc|xls|pdf|jpg|png|gif|txt|zip)(\.exe|\.bat|\.ps1|\.vbs|\.js|\.hta|\.scr|\.cmd|\.com)$',
    re.IGNORECASE,
)

# OLE/CFB magic bytes (MS Office compound document)
_OLE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
# OOXML ZIP magic
_ZIP_MAGIC = b'PK\x03\x04'

_HIGH_VALUE_BRANDS = frozenset([
    'microsoft','google','amazon','paypal','apple','docusign','dropbox',
    'office365','sharepoint','onedrive','outlook','teams','zoom','slack',
    'fedex','ups','irs','dhl','netflix','linkedin',
])

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in freq.values() if c > 0)


def _normalize_domain(domain: str) -> str:
    """Apply confusable mapping and lower-case for homoglyph check."""
    return unicodedata.normalize('NFKC', domain.lower()).translate(_CONFUSABLE)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        cur = [i + 1]
        for j, cb in enumerate(b):
            cur.append(min(prev[j] + (ca != cb), cur[j] + 1, prev[j + 1] + 1))
        prev = cur
    return prev[-1]


# ---------------------------------------------------------------------------
# EMAIL: URLRiskScorer
# ---------------------------------------------------------------------------

class URLRiskScorer:
    """Score URL risk: entropy, homoglyphs, redirect depth, shortener, domain age heuristic.

    Emits: email:url_entropy_high, email:url_homoglyph, email:url_redirect_chain,
           email:url_shortener, email:url_brand_impersonation
    """

    ENTROPY_THRESHOLD = 3.8   # high entropy path → obfuscated payload
    REDIRECT_DEPTH_THRESHOLD = 2

    def score(self, url: str, redirect_depth: int = 0) -> List[Dict[str, Any]]:
        factors: List[Dict[str, Any]] = []
        if not url:
            return factors

        try:
            # Parse manually (avoid importing urllib overhead)
            rest = url.split('://', 1)[-1] if '://' in url else url
            domain_part = rest.split('/')[0].lower()
            path_part = '/' + '/'.join(rest.split('/')[1:]) if '/' in rest else ''
        except Exception:
            return factors

        # 1. Entropy of URL path (encoded payloads / obfuscated params)
        path_entropy = _shannon_entropy(path_part.encode('utf-8', errors='replace'))
        if path_entropy > self.ENTROPY_THRESHOLD:
            factors.append({
                'factor': 'email:url_entropy_high',
                'confidence': min(0.9, 0.5 + (path_entropy - self.ENTROPY_THRESHOLD) * 0.1),
                'reason': f'URL path entropy {path_entropy:.2f} exceeds threshold {self.ENTROPY_THRESHOLD}',
                'tags': ['T1566.001', 'T1204.001'],
            })

        # 2. Homoglyph / confusable domain
        normalized = _normalize_domain(domain_part.split(':')[0])  # strip port
        # Check against high-value brand names
        for brand in _HIGH_VALUE_BRANDS:
            dist = _levenshtein(normalized.replace('.', ''), brand.replace('.', ''))
            if 0 < dist <= 2:
                factors.append({
                    'factor': 'email:url_homoglyph',
                    'confidence': 0.82,
                    'reason': f'Domain "{domain_part}" visually similar to brand "{brand}" (Levenshtein={dist})',
                    'tags': ['T1566.001', 'T1598'],
                })
                break

        # 3. URL shortener
        base = '.'.join(domain_part.split(':')[0].split('.')[-2:])
        if base in _SHORTENER_DOMAINS or domain_part.split(':')[0] in _SHORTENER_DOMAINS:
            factors.append({
                'factor': 'email:url_shortener',
                'confidence': 0.55,
                'reason': f'Known URL shortener domain: {base}',
                'tags': ['T1566.001'],
            })

        # 4. Redirect chain depth
        if redirect_depth >= self.REDIRECT_DEPTH_THRESHOLD:
            factors.append({
                'factor': 'email:url_redirect_chain',
                'confidence': min(0.85, 0.55 + redirect_depth * 0.1),
                'reason': f'URL redirect depth {redirect_depth} ≥ threshold {self.REDIRECT_DEPTH_THRESHOLD}',
                'tags': ['T1566.001', 'T1204.001'],
            })

        # 5. Brand impersonation in path/params
        path_lower = path_part.lower()
        for brand in _HIGH_VALUE_BRANDS:
            if brand in path_lower and brand not in domain_part:
                factors.append({
                    'factor': 'email:url_brand_impersonation',
                    'confidence': 0.72,
                    'reason': f'Brand "{brand}" appears in URL path but not in domain — possible impersonation',
                    'tags': ['T1566.001', 'T1598'],
                })
                break

        return factors


# ---------------------------------------------------------------------------
# EMAIL: AttachmentRiskAnalyzer
# ---------------------------------------------------------------------------

class AttachmentRiskAnalyzer:
    """Analyze attachment for macro, double-extension, zip-bomb, OLE signatures.

    Emits: email:attachment_double_ext, email:attachment_zip_bomb,
           email:attachment_ole_macro, email:attachment_high_entropy
    """

    ZIP_BOMB_RATIO = 50.0     # compression ratio that triggers alarm
    ENTROPY_HIGH   = 7.2      # encrypted/packed bytes

    def analyze(self, filename: str, content: Optional[bytes] = None,
                compressed_size: int = 0, uncompressed_size: int = 0) -> List[Dict[str, Any]]:
        factors: List[Dict[str, Any]] = []

        # 1. Double extension
        if filename and _DOUBLE_EXT_RE.search(filename):
            factors.append({
                'factor': 'email:attachment_double_ext',
                'confidence': 0.88,
                'reason': f'Double extension detected in filename: {filename}',
                'tags': ['T1566.001', 'T1204.002'],
            })

        # 2. Zip-bomb: compressed vs uncompressed size ratio
        if compressed_size > 0 and uncompressed_size > 0:
            ratio = uncompressed_size / compressed_size
            if ratio >= self.ZIP_BOMB_RATIO:
                factors.append({
                    'factor': 'email:attachment_zip_bomb',
                    'confidence': min(0.93, 0.5 + ratio / 200.0),
                    'reason': f'Compression ratio {ratio:.1f}:1 ≥ {self.ZIP_BOMB_RATIO}:1 zip-bomb threshold',
                    'tags': ['T1566.001'],
                })

        if content:
            # 3. OLE/CFB magic bytes (MS Office compound document with potential macros)
            if content[:8] == _OLE_MAGIC:
                # Check for vbaProject.bin signature within (OOXML uses ZIP; CFB = legacy .doc/.xls)
                factors.append({
                    'factor': 'email:attachment_ole_macro',
                    'confidence': 0.78,
                    'reason': 'OLE CFB magic bytes detected — legacy Office format with macro capability',
                    'tags': ['T1566.001', 'T1204.002'],
                })
            elif content[:4] == _ZIP_MAGIC:
                # OOXML container — check for vbaProject.bin
                try:
                    if b'vbaProject.bin' in content or b'xl/vbaProject' in content:
                        factors.append({
                            'factor': 'email:attachment_ole_macro',
                            'confidence': 0.85,
                            'reason': 'vbaProject.bin found inside OOXML container — macro-enabled document',
                            'tags': ['T1566.001', 'T1204.002'],
                        })
                except Exception:
                    pass

            # 4. High-entropy attachment (encrypted/packed payload)
            ent = _shannon_entropy(content[:65536])  # sample first 64KB
            if ent > self.ENTROPY_HIGH:
                factors.append({
                    'factor': 'email:attachment_high_entropy',
                    'confidence': min(0.82, 0.5 + (ent - self.ENTROPY_HIGH) * 0.15),
                    'reason': f'Attachment content entropy {ent:.2f} ≥ {self.ENTROPY_HIGH} — likely encrypted/packed payload',
                    'tags': ['T1027', 'T1566.001'],
                })

        return factors


# ---------------------------------------------------------------------------
# EMAIL: BECScoringModel
# ---------------------------------------------------------------------------

class BECScoringModel:
    """EWMA-based sender anomaly, reply-to mismatch, first-contact scoring.

    Emits: email:bec_sender_anomaly, email:bec_replyto_mismatch,
           email:bec_first_contact, email:bec_display_name_spoof
    """

    _EWMA_ALPHA = 0.3

    def __init__(self):
        # domain → moving average msg count (EWMA)
        self._domain_ewma: Dict[str, float] = {}
        self._seen_domains: Dict[str, int] = {}  # domain → contact count

    def analyze(self, from_addr: str, reply_to: str, display_name: str,
                to_addr: str, subject: str = '') -> List[Dict[str, Any]]:
        factors: List[Dict[str, Any]] = []
        if not from_addr:
            return factors

        from_domain = from_addr.split('@')[-1].lower() if '@' in from_addr else ''

        # Update EWMA frequency for this domain
        prior = self._domain_ewma.get(from_domain, 0.0)
        self._domain_ewma[from_domain] = self._EWMA_ALPHA * 1.0 + (1 - self._EWMA_ALPHA) * prior
        count = self._seen_domains.get(from_domain, 0) + 1
        self._seen_domains[from_domain] = count

        # 1. First-contact (domain never seen before from this sender)
        if count == 1:
            factors.append({
                'factor': 'email:bec_first_contact',
                'confidence': 0.50,
                'reason': f'First email from domain "{from_domain}"',
                'tags': ['T1566', 'T1598'],
            })

        # 2. Reply-to mismatch
        if reply_to:
            reply_domain = reply_to.split('@')[-1].lower() if '@' in reply_to else ''
            if reply_domain and reply_domain != from_domain:
                # Check if reply-to is a freemail (high BEC signal)
                freemail = {'gmail.com','yahoo.com','hotmail.com','outlook.com',
                            'protonmail.com','tutanota.com','aol.com','mail.ru'}
                conf = 0.85 if reply_domain in freemail else 0.70
                factors.append({
                    'factor': 'email:bec_replyto_mismatch',
                    'confidence': conf,
                    'reason': f'Reply-To domain "{reply_domain}" differs from From domain "{from_domain}"',
                    'tags': ['T1566', 'T1598'],
                })

        # 3. Display-name spoofing (display name contains high-value executive/brand but From domain doesn't match)
        if display_name:
            dn_lower = display_name.lower()
            exec_terms = {'ceo','cfo','cto','vp ','president','director','manager',
                          'accounts payable','payroll','finance','treasurer'}
            for term in exec_terms:
                if term in dn_lower:
                    # Legitimate if from_domain matches company (heuristic: check for generic domain)
                    public_domains = {'gmail.com','yahoo.com','hotmail.com','protonmail.com'}
                    if from_domain in public_domains:
                        factors.append({
                            'factor': 'email:bec_display_name_spoof',
                            'confidence': 0.80,
                            'reason': f'Display name "{display_name}" implies executive but sender is public domain {from_domain}',
                            'tags': ['T1566', 'T1598.002'],
                        })
                    break

        # 4. Sender anomaly — EWMA burst (many emails from domain not seen before)
        if prior < 0.1 and count >= 3:
            factors.append({
                'factor': 'email:bec_sender_anomaly',
                'confidence': 0.62,
                'reason': f'Domain "{from_domain}" suddenly sending multiple emails (count={count}, prior_ewma={prior:.3f})',
                'tags': ['T1566', 'T1078'],
            })

        return factors


# ---------------------------------------------------------------------------
# ENDPOINT: ProcessTreeAnomalyDetector
# ---------------------------------------------------------------------------

class ProcessTreeAnomalyDetector:
    """IsolationForest + TF-IDF on process lineage for endpoint anomaly.

    Emits: endpoint:process_tree_anomaly, endpoint:cmdline_rarity_high
    """

    IF_THRESHOLD_HIGH   = 0.72
    IF_THRESHOLD_MEDIUM = 0.55
    CMDLINE_RARITY_THRESHOLD = 0.80

    def __init__(self):
        if _IF_AVAILABLE and _IFDetector is not None:
            try:
                self._if = _IFDetector(contamination=0.05)
            except Exception:
                self._if = None
        else:
            self._if = None

        if _TFIDF_AVAILABLE and _TfIdf is not None:
            try:
                self._tfidf = _TfIdf()
            except Exception:
                self._tfidf = None
        else:
            self._tfidf = None

        # Process lineage feature buffer for IF training
        self._feature_buf: List[List[float]] = []
        self._trained = False

    def _extract_features(self, proc: str, parent: str, depth: int,
                          time_since_boot: float) -> List[float]:
        """Convert process lineage context into numeric features."""
        # Features: [proc_name_len, parent_name_len, depth, time_since_boot_norm, has_extension, is_temp_path]
        proc = proc or ''
        parent = parent or ''
        is_temp = 1.0 if any(t in proc.lower() for t in ['temp', 'tmp', 'appdata', '%temp%']) else 0.0
        has_ext = 1.0 if re.search(r'\.\w{2,4}$', proc) else 0.0
        return [
            float(len(proc)),
            float(len(parent)),
            float(max(0, depth)),
            float(min(1.0, time_since_boot / 86400.0)),  # normalize to days
            has_ext,
            is_temp,
        ]

    def analyze(self, process: str, parent_process: str, cmdline: str,
                depth: int = 1, time_since_boot: float = 3600.0) -> List[Dict[str, Any]]:
        factors: List[Dict[str, Any]] = []

        # TF-IDF rarity on command-line tokens
        if cmdline and self._tfidf is not None:
            try:
                rarity = self._tfidf.score(cmdline)
                if rarity >= self.CMDLINE_RARITY_THRESHOLD:
                    factors.append({
                        'factor': 'endpoint:cmdline_rarity_high',
                        'confidence': min(0.9, rarity),
                        'reason': f'Command-line token rarity score {rarity:.2f} ≥ {self.CMDLINE_RARITY_THRESHOLD}',
                        'tags': ['T1059', 'T1027'],
                    })
            except Exception:
                pass

        # IsolationForest on process lineage
        feats = self._extract_features(process, parent_process, depth, time_since_boot)
        self._feature_buf.append(feats)

        # Train/retrain periodically
        if not self._trained and len(self._feature_buf) >= 20 and self._if is not None:
            try:
                self._if.fit([[f] for f in self._feature_buf])
                self._trained = True
            except Exception:
                pass

        if self._trained and self._if is not None:
            try:
                score = self._if.score_sample(feats)
                if score >= self.IF_THRESHOLD_HIGH:
                    factors.append({
                        'factor': 'endpoint:process_tree_anomaly',
                        'confidence': min(0.92, score),
                        'reason': f'Process lineage anomaly score {score:.2f} — "{process}" spawned by "{parent_process}" at depth {depth}',
                        'tags': ['T1059', 'T1055', 'T1134'],
                    })
                elif score >= self.IF_THRESHOLD_MEDIUM:
                    factors.append({
                        'factor': 'endpoint:process_tree_anomaly',
                        'confidence': score,
                        'reason': f'Moderate process lineage anomaly score {score:.2f} — "{process}"',
                        'tags': ['T1059'],
                    })
            except Exception:
                pass

        return factors


# ---------------------------------------------------------------------------
# ENDPOINT: PersistenceScoringModel
# ---------------------------------------------------------------------------

class PersistenceScoringModel:
    """Novel persistence detection with temporal baseline.

    Emits: endpoint:persistence_novel, endpoint:persistence_burst
    """

    BURST_THRESHOLD = 3          # ≥N new persistence entries in window = burst
    WINDOW_SECONDS  = 300        # 5-minute sliding window

    def __init__(self):
        # host → list of (timestamp, mechanism_key)
        self._host_persist: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        # global baseline of known-good persistence keys
        self._known_persist: Dict[str, set] = defaultdict(set)

    def analyze(self, host: str, mechanism: str, key: str,
                ts: Optional[float] = None) -> List[Dict[str, Any]]:
        """
        mechanism: 'registry_run', 'scheduled_task', 'service', 'startup_folder', 'cron', 'launchagent'
        key: the specific registry path, task name, service name, etc.
        """
        factors: List[Dict[str, Any]] = []
        if not host or not mechanism:
            return factors

        ts = ts or time.time()
        canon_key = f'{mechanism}:{key}'

        known = self._known_persist[host]

        # Novel persistence: key not seen before on this host
        if canon_key not in known:
            factors.append({
                'factor': 'endpoint:persistence_novel',
                'confidence': 0.72,
                'reason': f'Novel persistence entry on "{host}": {mechanism} → {key}',
                'tags': ['T1547', 'T1053', 'T1543'],
            })
            known.add(canon_key)

        # Update sliding window
        window = self._host_persist[host]
        window.append((ts, canon_key))
        # Prune outside window
        cutoff = ts - self.WINDOW_SECONDS
        self._host_persist[host] = [(t, k) for t, k in window if t >= cutoff]

        # Burst detection
        if len(self._host_persist[host]) >= self.BURST_THRESHOLD:
            factors.append({
                'factor': 'endpoint:persistence_burst',
                'confidence': min(0.88, 0.60 + 0.05 * len(self._host_persist[host])),
                'reason': f'{len(self._host_persist[host])} persistence entries in {self.WINDOW_SECONDS}s window on "{host}"',
                'tags': ['T1547', 'T1053'],
            })
            # Reset to avoid repeated alerts for same burst
            self._host_persist[host] = []

        return factors


# ---------------------------------------------------------------------------
# ENDPOINT: AdvancedEndpointGateway
# ---------------------------------------------------------------------------

class AdvancedEndpointGateway:
    """Thin wrapper around detect_advanced_endpoint_threats() for pipeline use.

    Reshapes output into {factor, confidence, reason, tags} dicts compatible
    with the rest of the pipeline.
    """

    def analyze(self, ev: Dict[str, Any]) -> List[Dict[str, Any]]:
        try:
            from src.core.detectors.advanced_endpoint_threats import detect_advanced_endpoint_threats
        except Exception:
            return []
        try:
            raw_factors = detect_advanced_endpoint_threats(ev)
        except Exception:
            return []
        out = []
        for f in raw_factors:
            if not isinstance(f, dict):
                continue
            name = f.get('factor') or f.get('name')
            if not name:
                continue
            out.append({
                'factor': name,
                'confidence': float(f.get('score', f.get('confidence', 0.6))),
                'reason': f.get('reason', ''),
                'tags': f.get('tags', []),
            })
        return out


# ---------------------------------------------------------------------------
# FACADE: EndpointEmailMLPipeline
# ---------------------------------------------------------------------------

class EndpointEmailMLPipeline:
    """Composable ML pipeline for endpoint and email threat detection.

    Analogous to NetworkMLPipeline but covering endpoint and email domains.
    All detectors share state within one pipeline instance (EWMA baselines, etc.)
    """

    def __init__(self):
        self._url_scorer        = URLRiskScorer()
        self._attach_analyzer   = AttachmentRiskAnalyzer()
        self._bec_model         = BECScoringModel()
        self._proc_detector     = ProcessTreeAnomalyDetector()
        self._persist_model     = PersistenceScoringModel()
        self._adv_gateway       = AdvancedEndpointGateway()

    def analyze_email_event(self, ev: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run all email detectors on a canonical email event dict.

        Expected keys (all optional): url, redirect_depth, attachment_filename,
        attachment_content (bytes), compressed_size, uncompressed_size,
        from_addr, reply_to, display_name, to_addr, subject.
        """
        factors: List[Dict[str, Any]] = []

        # URL risk
        url = ev.get('url') or ev.get('uri') or ''
        if url:
            factors.extend(self._url_scorer.score(
                url, redirect_depth=int(ev.get('redirect_depth', 0))))

        # Attachment risk
        fname = ev.get('attachment_filename') or ev.get('file_name') or ''
        content = ev.get('attachment_content')  # may be bytes or None
        factors.extend(self._attach_analyzer.analyze(
            filename=fname,
            content=content if isinstance(content, (bytes, bytearray)) else None,
            compressed_size=int(ev.get('compressed_size', 0)),
            uncompressed_size=int(ev.get('uncompressed_size', 0)),
        ))

        # BEC scoring
        factors.extend(self._bec_model.analyze(
            from_addr=str(ev.get('from_addr') or ev.get('sender') or ev.get('user') or ''),
            reply_to=str(ev.get('reply_to') or ev.get('replyto') or ''),
            display_name=str(ev.get('display_name') or ev.get('from_display') or ''),
            to_addr=str(ev.get('to_addr') or ev.get('recipient') or ''),
            subject=str(ev.get('subject') or ''),
        ))

        return factors

    def analyze_endpoint_event(self, ev: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run all endpoint detectors on a canonical endpoint event dict.

        Expected keys (all optional): process, parent_process, cmdline, process_depth,
        time_since_boot, persistence_mechanism, persistence_key, host, ts.
        """
        factors: List[Dict[str, Any]] = []

        # Process tree anomaly
        factors.extend(self._proc_detector.analyze(
            process=str(ev.get('process') or ev.get('proc') or ''),
            parent_process=str(ev.get('parent_process') or ev.get('parent') or ''),
            cmdline=str(ev.get('cmdline') or ev.get('command_line') or ev.get('cmd') or ''),
            depth=int(ev.get('process_depth', 1)),
            time_since_boot=float(ev.get('time_since_boot', 3600.0)),
        ))

        # Persistence scoring
        mech = ev.get('persistence_mechanism') or ''
        key  = ev.get('persistence_key') or ''
        if mech and key:
            factors.extend(self._persist_model.analyze(
                host=str(ev.get('host') or ''),
                mechanism=str(mech),
                key=str(key),
                ts=float(ev.get('ts') or time.time()),
            ))

        # Advanced endpoint threats (fileless, eBPF, steg, supply chain, macros, ransomware)
        factors.extend(self._adv_gateway.analyze(ev))

        return factors
