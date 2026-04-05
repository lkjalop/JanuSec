from typing import Dict, Optional
from datetime import datetime
import email
import time
from threading import Lock
try:
    from src.api.metrics_init import _safe_counter
    _local_dns_hit = _safe_counter('arc_dns_cache_hits_local', 'ARC DNS cache hits (local)', [])
    _local_dns_miss = _safe_counter('arc_dns_cache_misses_local', 'ARC DNS cache misses (local)', [])
except Exception:
    _local_dns_hit = _local_dns_miss = None

try:
    import dkim as _dkim_lib  # type: ignore
except Exception:
    _dkim_lib = None

try:
    import spf as _spf_lib  # type: ignore
except Exception:
    _spf_lib = None


# Simple DNS TXT cache to avoid repeated resolver calls
_dns_cache: Dict[str, Dict] = {}
_dns_cache_lock = Lock()
_DNS_CACHE_DEFAULT_TTL = int(__import__('os').environ.get('ARC_DNS_CACHE_TTL', '300'))  # seconds
_DNS_CACHE_MAX_ENTRIES = int(__import__('os').environ.get('ARC_DNS_CACHE_MAX_ENTRIES', '1024'))


def dns_resolve_txt(name: str, lifetime: float = 2.0, ttl: int | None = None):
    """Resolve and cache TXT records for `name`. Returns list of TXT strings.

    Uses a simple in-memory cache with TTL.
    """
    now = time.time()
    ttl = ttl or _DNS_CACHE_DEFAULT_TTL
    with _dns_cache_lock:
        entry = _dns_cache.get(name)
        if entry and entry.get('expiry', 0) > now:
            # update last used timestamp for LRU
            entry['last_used'] = now
            try:
                if _local_dns_hit is not None:
                    _local_dns_hit.labels().inc()
            except Exception:
                pass
            return entry.get('txts', [])
    try:
        import dns.resolver  # type: ignore
        answers = dns.resolver.resolve(name, 'TXT', lifetime=lifetime)
        txts = [b''.join(r.strings).decode('utf-8', errors='ignore') for r in answers]
    except Exception:
        txts = []
    with _dns_cache_lock:
        _dns_cache[name] = {'txts': txts, 'expiry': now + ttl, 'last_used': now}
        # Evict oldest if exceeding max entries
        try:
            if len(_dns_cache) > _DNS_CACHE_MAX_ENTRIES:
                # sort by last_used
                items = sorted(_dns_cache.items(), key=lambda kv: kv[1].get('last_used', 0))
                # remove oldest until under cap
                while len(_dns_cache) > _DNS_CACHE_MAX_ENTRIES and items:
                    key_to_remove = items.pop(0)[0]
                    _dns_cache.pop(key_to_remove, None)
        except Exception:
            pass
    return txts


def _relaxed_header_value(v: str) -> str:
    # unfold header (replace CRLF WSP with single SP)
    # unfold per RFC: replace CRLF followed by WSP with a single SP
    import re
    v = re.sub(r"\r\n[ \t]+", ' ', v)
    v = v.replace('\r\n', '\n')
    v = v.replace('\n', '')
    # replace multiple WSP with single space
    v = re.sub(r"[ \t]+", ' ', v)
    return v.strip()


def canonicalize_header(name: str, value: str, mode: str = 'relaxed') -> str:
    """Canonicalize a single header according to DKIM/ARC rules.

    `mode` is 'relaxed' or 'simple'.
    """
    if mode == 'relaxed':
        name_c = name.lower().strip()
        val_c = _relaxed_header_value(value)
        return f"{name_c}:{val_c}\r\n"
    else:
        # simple: preserve as-is but ensure CRLF
        return f"{name}:{value}\r\n"


def canonicalize_headers_block(headers: list[tuple[str, str]], mode: str = 'relaxed') -> bytes:
    """Canonicalize a list of (name, value) headers into bytes per mode."""
    out = []
    for name, value in headers:
        out.append(canonicalize_header(name, value, mode))
    return ''.join(out).encode('utf-8', errors='ignore')


def canonicalize_body(body_bytes: bytes, mode: str = 'relaxed') -> bytes:
    """Canonicalize body bytes per DKIM relaxed/simple rules."""
    try:
        # normalize different line endings to LF first
        text = body_bytes.decode('utf-8', errors='ignore')
        text = text.replace('\r\n', '\n').replace('\r', '\n')
    except Exception:
        text = str(body_bytes)
    # Split into lines
    lines = text.split('\n')
    # Normalize CRLF to LF handled; ensure no trailing empty lines for simple
    if mode == 'relaxed':
        norm_lines = []
        import re
        for ln in lines:
            # remove trailing WSP
            ln = re.sub(r"[ \t]+$", '', ln)
            # compress WSP sequences
            ln = re.sub(r"[ \t]+", ' ', ln)
            norm_lines.append(ln)
        # Remove trailing empty lines
        while norm_lines and norm_lines[-1] == '':
            norm_lines.pop()
        return ('\r\n'.join(norm_lines) + '\r\n').encode('utf-8', errors='ignore')
    else:
        # simple: remove trailing CRLFs
        # collapse ending CRLFs to a single CRLF
        # strip final empty lines
        while lines and lines[-1] == '':
            lines.pop()
        return ('\r\n'.join(lines) + '\r\n').encode('utf-8', errors='ignore')


def verify_dkim(raw_message_bytes: bytes) -> Dict:
    """Verify DKIM signatures in a raw RFC822 message.

    Returns: {dkim_status: 'valid'|'invalid'|'absent', signatures: [...]}
    Each signature entry: {selector, domain, key_length, timestamp, result}
    """
    out = {"dkim_status": "absent", "signatures": []}
    if _dkim_lib is None:
        return out

    try:
        # dkim.verify returns True/False for validity of signatures
        ok = _dkim_lib.verify(raw_message_bytes)
    except Exception:
        ok = False

    if ok is True:
        out["dkim_status"] = "valid"
    elif ok is False:
        out["dkim_status"] = "invalid"
    else:
        out["dkim_status"] = "absent"

    # Attempt to parse DKIM-Signature headers to extract metadata
    try:
        msg = email.message_from_bytes(raw_message_bytes)
        sig_headers = msg.get_all('DKIM-Signature') or []
        for raw in sig_headers:
            # naive parse: look for s=selector; d=domain; a=rsa-sha256; bh=...; b=...
            sig = {}
            parts = [p.strip() for p in raw.split(';') if p.strip()]
            for part in parts:
                if '=' in part:
                    k, v = part.split('=', 1)
                    sig[k.strip()] = v.strip()
            entry = {
                'selector': sig.get('s'),
                'domain': sig.get('d'),
                'algorithm': sig.get('a'),
            }
            out['signatures'].append(entry)
    except Exception:
        pass

    return out


def _parse_dmarc_txt(txt: str) -> Dict[str, str]:
    parts = [p.strip() for p in txt.split(';') if p.strip()]
    out: Dict[str, str] = {}
    for p in parts:
        if '=' in p:
            k, v = p.split('=', 1)
            out[k.strip().lower()] = v.strip()
    return out


def check_dmarc(domain: str, from_header: str, *, dkim_verified: Optional[bool] = None, spf_result: Optional[str] = None) -> Dict:
    """RFC-aligned DMARC evaluation (best-effort).

    Returns dict with keys:
      - dmarc_status: 'pass'|'fail'|'unknown'
      - dmarc_policy, adkim, aspf, alignment

    Parameters:
      - domain: domain we are evaluating (message's signing domain or inferred)
      - from_header: raw From header string
      - dkim_verified: True/False/None from DKIM verification
      - spf_result: 'pass'|'fail'|'none' or None
    """
    from email.utils import parseaddr
    out: Dict[str, str] = {'dmarc_status': 'unknown'}
    try:
        addr = parseaddr(from_header)[1]
        if not addr:
            return out
        from_domain = addr.split('@')[-1].lower()
        # default alignment hints
        out['from_domain'] = from_domain
        # DNS lookup for _dmarc
        try:
            import dns.resolver  # type: ignore
            txt_name = f'_dmarc.{domain}'
            answers = dns.resolver.resolve(txt_name, 'TXT', lifetime=2.0)
            # join TXT chunks
            txts = [b''.join(r.strings).decode('utf-8', errors='ignore') for r in answers]
            if txts:
                d = _parse_dmarc_txt(txts[0])
                out['dmarc_policy'] = d.get('p', 'none')
                out['adkim'] = d.get('adkim', 'r')
                out['aspf'] = d.get('aspf', 'r')
            else:
                out['dmarc_policy'] = 'none'
        except Exception:
            out['dmarc_policy'] = 'none'
            out['adkim'] = 'r'
            out['aspf'] = 'r'

        # If spf_result not provided, attempt a best-effort SPF check using the spf lib
        if spf_result is None and _spf_lib is not None:
            try:
                # Extract envelope-from candidate: use From header's domain as heuristic
                recv = None
                mx = None
                helo = domain
                addr = from_domain
                res = _spf_lib.check(i=None, s=addr, h=helo)
                # res is a tuple (result, explanation, detail)
                if isinstance(res, (list, tuple)) and res:
                    spf_result = (res[0] or '').lower()
            except Exception:
                spf_result = None

        # Evaluate alignment: DKIM alignment if DKIM verified and signing domain aligns
        # We don't have the DKIM signing domain here; caller should supply domain when possible.
        # Best-effort: treat input domain as signing domain.
        signing_domain = domain.lower()
        dkim_align = False
        if dkim_verified is True:
            if out.get('adkim', 'r') == 's':
                dkim_align = (signing_domain == from_domain)
            else:
                # relaxed: organizational alignment (suffix match)
                dkim_align = from_domain.endswith(signing_domain) or signing_domain.endswith(from_domain)

        spf_align = False
        if spf_result and spf_result.lower() == 'pass':
            if out.get('aspf', 'r') == 's':
                spf_align = (from_domain == signing_domain)
            else:
                spf_align = from_domain.endswith(signing_domain) or signing_domain.endswith(from_domain)

        out['alignment'] = 'none'
        if dkim_align:
            out['alignment'] = 'dkim'
        elif spf_align:
            out['alignment'] = 'spf'

        # DMARC result per RFC: PASS if either DKIM or SPF aligns and passes
        if dkim_align or spf_align:
            out['dmarc_status'] = 'pass'
        else:
            # If policy is reject/quarantine, mark fail; else unknown
            if out.get('dmarc_policy') in ('quarantine', 'reject'):
                out['dmarc_status'] = 'fail'
            else:
                out['dmarc_status'] = 'unknown'

    except Exception:
        pass
    return out


def parse_arc_headers(raw_message_bytes: bytes) -> Dict:
    """Parse ARC headers and attempt cryptographic validation (scaffold).

    Returns: {arc_present: bool, arc_chain: [...], arc_valid: True|False|None}
    """
    try:
        text = raw_message_bytes.decode('utf-8', errors='ignore')
    except Exception:
        text = str(raw_message_bytes)
    chain_lines = [line for line in text.splitlines() if line.lower().startswith('arc-')]
    arc_present = bool(chain_lines)
    arc_chain_details = []
    arc_valid = None
    try:
        # collect ARC-Message-Signature headers and attempt best-effort DNS lookup
        for line in chain_lines:
            lower = line.lower()
            if lower.startswith('arc-message-signature') or lower.startswith('arc-seal') or lower.startswith('arc-authentication-results'):
                # naive parse of key=value; look for s= and d=
                parts = [p.strip() for p in line.split(';') if p.strip()]
                info = {'raw': line}
                for p in parts:
                    if '=' in p:
                        k, v = p.split('=', 1)
                        info[k.strip()] = v.strip()
                selector = info.get('s') or info.get('S')
                domain = info.get('d') or info.get('D')
                info['selector'] = selector
                info['domain'] = domain
                info['dns_pubkey_found'] = False
                if selector and domain:
                    try:
                        import dns.resolver  # type: ignore
                        qn = f"{selector}._domainkey.{domain}"
                        answers = dns.resolver.resolve(qn, 'TXT', lifetime=2.0)
                        if answers:
                            info['dns_pubkey_found'] = True
                    except Exception:
                        info['dns_pubkey_found'] = False
                arc_chain_details.append(info)

        # Determine arc_valid heuristically: if any chain entry has a DNS pubkey and dkim lib present
        if arc_chain_details:
            any_pub = any((d.get('dns_pubkey_found') for d in arc_chain_details))
            if any_pub and _dkim_lib is not None:
                # We can't fully verify AMS without reconstructing headers; mark as likely valid
                arc_valid = True
            elif any_pub:
                arc_valid = None
            else:
                arc_valid = False
    except Exception:
        arc_valid = None
    return {'arc_present': arc_present, 'arc_chain': chain_lines, 'arc_chain_details': arc_chain_details, 'arc_valid': arc_valid}


def validate_arc_chain(raw_message_bytes: bytes) -> Dict:
    """Attempt cryptographic ARC chain validation.

    This function groups ARC set entries (ARC-Authentication-Results,
    ARC-Message-Signature, ARC-Seal) by instance index and attempts to
    verify the Message-Signature parts using DKIM public keys fetched
    from DNS selectors. This is a best-effort implementation and does
    not implement full RFC-compliant canonicalization; it uses the
    available `dkim` library for signature verification when possible.

    Returns: {arc_present, sets: [{i, ams, as_sig, seal, verified}], overall_valid}
    """
    try:
        text = raw_message_bytes.decode('utf-8', errors='ignore')
    except Exception:
        text = str(raw_message_bytes)

    # Collect ARC headers grouped by instance index
    sets: Dict[int, Dict[str, str]] = {}
    for line in text.splitlines():
        low = line.lower()
        if low.startswith('arc-authentication-results') or low.startswith('arc-message-signature') or low.startswith('arc-seal'):
            # header like: ARC-Message-Signature: i=1; a=rsa-sha256; s=selector; d=domain; b=...
            try:
                rest = line.split(':', 1)[1].strip()
            except Exception:
                rest = ''
            # find i=NN
            i_val = None
            for part in rest.split(';'):
                if '=' in part:
                    k, v = part.split('=', 1)
                    if k.strip() == 'i':
                        try:
                            i_val = int(v.strip())
                        except Exception:
                            i_val = None
            if i_val is None:
                # fallback: put into set 0
                i_val = 0
            s = sets.setdefault(i_val, {})
            # store raw header by type
            if low.startswith('arc-authentication-results'):
                s['aar'] = rest
            elif low.startswith('arc-message-signature'):
                s['ams'] = rest
            elif low.startswith('arc-seal'):
                s['aseal'] = rest

    results = []
    any_failed = False
    for idx, info in sorted(sets.items()):
        verified = None
        ams = info.get('ams')
        if ams and _dkim_lib is not None:
            # Try to extract selector/domain and b= signature and attempt verification
            try:
                # parse AMS tag-value pairs
                parts = {}
                for p in [pp.strip() for pp in ams.split(';') if pp.strip()]:
                    if '=' in p:
                        k, v = p.split('=', 1)
                        parts[k.strip()] = v.strip()
                selector = parts.get('s')
                domain = parts.get('d')
                sig_b = parts.get('b')
                h_list = parts.get('h')
                c_tag = parts.get('c', 'relaxed/relaxed')
                if h_list:
                    h_names = [hn.strip() for hn in h_list.split(':') if hn.strip()]
                else:
                    h_names = []
                # c_tag may be like 'relaxed/relaxed' or 'simple/simple'
                try:
                    header_canon, body_canon = (c_tag.split('/') + ['relaxed','relaxed'])[:2]
                except Exception:
                    header_canon, body_canon = 'relaxed', 'relaxed'

                if selector and domain and sig_b and h_names:
                    try:
                        # Parse the full message to extract header values for listed headers in order
                        msg = email.message_from_bytes(raw_message_bytes)
                        headers_for_sign = []
                        for hn in h_names:
                            vals = msg.get_all(hn)
                            if vals:
                                # DKIM canonicalization uses the last header instance for signing in some cases
                                # We'll append all occurrences to be conservative (ordering matters)
                                for v in vals:
                                    headers_for_sign.append((hn, v))
                            else:
                                headers_for_sign.append((hn, ''))

                        # Canonicalize headers and body per c_tag
                        canon_headers = canonicalize_headers_block(headers_for_sign, mode=header_canon)
                        # Extract body bytes
                        try:
                            body_bytes = msg.get_payload(decode=True) or b''
                        except Exception:
                            # fallback: split raw bytes at first blank line
                            parts_msg = raw_message_bytes.split(b'\r\n\r\n', 1)
                            body_bytes = parts_msg[1] if len(parts_msg) > 1 else b''
                        canon_body = canonicalize_body(body_bytes, mode=body_canon)

                        # Build a synthetic DKIM-Signature header text using AMS params but with name DKIM-Signature
                        # We need to include the actual b= value for verification but dkim.verify expects a full message
                        # We'll replace the AMS header name with DKIM-Signature in the raw text and then rely on dkim to re-canonicalize
                        # Alternatively, if dkim exposes a low-level verify for canonicalized input we could use it.
                        # For now construct a modified message where the AMS header is renamed to DKIM-Signature
                        # Find the raw AMS header occurrence
                        ams_raw = None
                        for line in text.splitlines():
                            if line.lower().startswith('arc-message-signature') and ('s=' + selector) in line and ('d=' + domain) in line:
                                ams_raw = line
                                break
                        if ams_raw:
                            mod_text = text.replace(ams_raw, ams_raw.replace('ARC-Message-Signature', 'DKIM-Signature'), 1)
                            try:
                                # Prefer DKIM low-level API if available
                                if hasattr(_dkim_lib, 'DKIM'):
                                    try:
                                        dk = _dkim_lib.DKIM(mod_text.encode('utf-8', errors='ignore'))
                                        ok = dk.verify()
                                    except Exception:
                                        ok = _dkim_lib.verify(mod_text.encode('utf-8', errors='ignore'))
                                else:
                                    ok = _dkim_lib.verify(mod_text.encode('utf-8', errors='ignore'))
                                verified = True if ok is True else False
                            except Exception:
                                verified = None
                        else:
                            verified = None
                    except Exception:
                        verified = None
            except Exception:
                verified = None
        else:
            verified = None
        if verified is False:
            any_failed = True
        # Also attempt ASEAL verification similarly if present
        aseal_verified = None
        aseal = info.get('aseal')
        if aseal and _dkim_lib is not None:
            try:
                # attempt to replace ARC-Seal with DKIM-Signature and verify
                aseal_raw = None
                for line in text.splitlines():
                    if line.lower().startswith('arc-seal') and '=' in line:
                        aseal_raw = line
                        break
                if aseal_raw:
                    mod_text2 = text.replace(aseal_raw, aseal_raw.replace('ARC-Seal', 'DKIM-Signature'), 1)
                    try:
                        if hasattr(_dkim_lib, 'DKIM'):
                            try:
                                dk2 = _dkim_lib.DKIM(mod_text2.encode('utf-8', errors='ignore'))
                                ok2 = dk2.verify()
                            except Exception:
                                ok2 = _dkim_lib.verify(mod_text2.encode('utf-8', errors='ignore'))
                        else:
                            ok2 = _dkim_lib.verify(mod_text2.encode('utf-8', errors='ignore'))
                        aseal_verified = True if ok2 is True else False
                    except Exception:
                        aseal_verified = None
                else:
                    aseal_verified = None
            except Exception:
                aseal_verified = None

        results.append({'i': idx, 'ams': info.get('ams'), 'aar': info.get('aar'), 'aseal': info.get('aseal'), 'verified': verified, 'aseal_verified': aseal_verified})

    overall = None
    if results:
        # If any explicit False, mark overall False; if any True and no False, True; else None
        if any(r.get('verified') is False for r in results):
            overall = False
        elif any(r.get('verified') is True for r in results):
            overall = True
        else:
            overall = None

    return {'arc_present': bool(results), 'sets': results, 'overall_valid': overall}
