from __future__ import annotations

from typing import List
import re
from urllib.parse import urlparse
from src.core.reputation import cache as repcache

# DNS resolver stub - import lazily to avoid hard dependency in test environments
dns_resolver = None

def _ensure_dns():
    global dns_resolver
    if dns_resolver is not None:
        return dns_resolver
    try:
        import dns.resolver as _dr
        dns_resolver = _dr
    except Exception:
        dns_resolver = None
    return dns_resolver

# Simple levenshtein for small strings
def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            add = prev[j] + 1
            delete = cur[j-1] + 1
            change = prev[j-1] + (0 if ca == cb else 1)
            cur.append(min(add, delete, change))
        prev = cur
    return prev[-1]

VIP_NAMES = {'ceo', 'chief executive officer', 'cto', 'cfo', 'coo', 'chief technology officer', 'john smith', 'jane doe'}
CORPORATE_DOMAINS = {'example.com', 'corp.example.com'}

def _parse_set_env(var: str) -> set[str]:
    try:
        import os
        val = os.getenv(var)
        if not val:
            return set()
        parts = [p.strip().lower() for p in val.split(',') if p.strip()]
        return set(parts)
    except Exception:
        return set()


def _normalize(s: str | None) -> str:
    if not s:
        return ''
    return s.strip().lower()


def display_name_spoof(headers: dict, body: str, vip_names: set[str] | None = None, corp_domains: set[str] | None = None) -> List[str]:
    factors = []
    try:
        frm = headers.get('From') or ''
        # simple parse: "Display Name" <user@domain>
        if '<' in frm and '>' in frm:
            display, addr = frm.split('<', 1)
            display = display.replace('"', '').strip()
            addr = addr.split('>')[0].strip()
        else:
            display = frm; addr = frm
        display_n = _normalize(display)
        domain = _normalize(addr.split('@')[-1]) if '@' in addr else ''
        vip = vip_names or VIP_NAMES
        corp = corp_domains or CORPORATE_DOMAINS
        # compare display tokens to VIP names
        for v in vip:
            if v in display_n and domain not in corp:
                factors.append('email:display_name_spoof')
                break
    except Exception:
        pass
    return factors


def financial_keywords(body: str) -> List[str]:
    factors = []
    try:
        terms = ['wire transfer', 'invoice', 'payment', 'bank account', 'swift', 'routing']
        bl = body.lower() if body else ''
        if any(t in bl for t in terms):
            factors.append('email:financial_keywords')
    except Exception:
        pass
    return factors


def urgency_keywords(body: str) -> List[str]:
    factors = []
    try:
        urgency_terms = ['urgent', 'immediate', 'verify account', 'suspended', 'unusual activity']
        bl = body.lower() if body else ''
        if any(t in bl for t in urgency_terms):
            factors.append('email:urgency_keywords')
    except Exception:
        pass
    return factors


def reply_to_mismatch(headers: dict) -> List[str]:
    factors = []
    try:
        frm = headers.get('From') or ''
        reply = headers.get('Reply-To') or ''
        if reply and '@' in reply and '@' in frm:
            d1 = reply.split('@')[-1].lower()
            d2 = frm.split('@')[-1].lower()
            if d1 != d2:
                factors.append('email:reply_to_mismatch')
    except Exception:
        pass
    return factors


def sender_spoofed_thread(headers: dict) -> List[str]:
    factors = []
    try:
        subj = headers.get('Subject') or ''
        if subj.lower().startswith('re:'):
            if not headers.get('In-Reply-To'):
                factors.append('email:sender_spoofed_thread')
    except Exception:
        pass
    return factors


# ---------------- URL Analysis detectors (Phase 2) ----------------
SHORTENERS = {'bit.ly','tinyurl.com','goo.gl','ow.ly','t.co'}
KNOWN_BRANDS = {'google.com','microsoft.com','facebook.com','apple.com'}


def _extract_urls(body: str) -> List[str]:
    if not body:
        return []
    # naive href and plain URLs
    urls = re.findall(r'https?://[^\s"\'<>]+', body)
    return urls


def url_shortener(body: str) -> List[str]:
    factors = []
    try:
        for u in _extract_urls(body):
            p = urlparse(u)
            if p.netloc.lower() in SHORTENERS:
                factors.append('email:url_shortener')
    except Exception:
        pass
    return factors


def url_ip_address(body: str) -> List[str]:
    factors = []
    try:
        pattern = re.compile(r'https?://(\d{1,3}(?:\.\d{1,3}){3})(?:[:/]|$)')
        if pattern.search(body or ''):
            factors.append('email:url_ip_address')
    except Exception:
        pass
    return factors


def url_login_keyword(body: str) -> List[str]:
    factors = []
    try:
        urls = _extract_urls(body)
        for u in urls:
            p = urlparse(u)
            if re.search(r'/(login|signin|verify|account|password|auth)', p.path, flags=re.I):
                factors.append('email:url_login_keyword')
                break
    except Exception:
        pass
    return factors


def url_typosquat(body: str) -> List[str]:
    factors = []
    try:
        urls = _extract_urls(body)
        for u in urls:
            p = urlparse(u)
            domain = p.netloc.split(':')[0].lower()
            for b in KNOWN_BRANDS:
                if domain == b:
                    continue
                if levenshtein(domain, b) <= 2:
                    factors.append('email:url_typosquat')
                    return factors
    except Exception:
        pass
    return factors


def link_domain_mismatch(body: str) -> List[str]:
    # Best-effort: find markdown-style [text](url) or <a> tags - fallback to path text mismatch
    factors = []
    try:
        # detect patterns like "<a href="http://evil.com">microsoft.com</a>"
        matches = re.findall(r'>([^<>]{1,60})<\/a>', body or '', flags=re.I)
        hrefs = re.findall(r'href=["\']([^"\']+)["\']', body or '', flags=re.I)
        for text, href in zip(matches, hrefs):
            try:
                txt_domain = re.sub(r'^.*@','', text).strip().lower()
                href_domain = urlparse(href).netloc.split(':')[0].lower()
                if txt_domain and href_domain and txt_domain != href_domain:
                    factors.append('email:link_domain_mismatch')
                    break
            except Exception:
                continue
    except Exception:
        pass
    return factors


def excessive_links(body: str) -> List[str]:
    factors = []
    try:
        urls = _extract_urls(body)
        if len(urls) > 5:
            factors.append('email:excessive_links')
    except Exception:
        pass
    return factors


# ---------------- Attachment detectors (Phase 3) ----------------
def double_extension(file_name: str | None) -> List[str]:
    factors = []
    try:
        if not file_name:
            return factors
        # detect patterns like invoice.pdf.exe
        if re.search(r"\.[a-z0-9]{1,6}\.[a-z0-9]{1,6}$", file_name.lower()):
            factors.append('email:double_extension')
    except Exception:
        pass
    return factors


def rtlo_filename(file_name: str | None) -> List[str]:
    factors = []
    try:
        if not file_name:
            return factors
        if '\u202e' in file_name:
            factors.append('email:rtlo_filename')
    except Exception:
        pass
    return factors


def iso_img_attachment(file_name: str | None, attachment_type: str | None) -> List[str]:
    factors = []
    try:
        fn = (file_name or '').lower()
        at = (attachment_type or '').lower()
        if fn.endswith('.iso') or fn.endswith('.img') or 'iso' in at:
            factors.append('email:iso_img_attachment')
    except Exception:
        pass
    return factors


def executable_in_archive(file_list: list | None) -> List[str]:
    factors = []
    try:
        if not file_list:
            return factors
        for f in file_list:
            if isinstance(f, str) and f.lower().endswith(('.exe', '.scr', '.bat', '.ps1')):
                factors.append('email:executable_in_archive')
                break
    except Exception:
        pass
    return factors


def password_protected_archive(meta: dict | None) -> List[str]:
    factors = []
    try:
        # meta may include keys like 'attachment_encrypted': True or 'content_disposition'
        if not meta:
            return factors
        if meta.get('attachment_encrypted') or meta.get('x_encrypted'):
            factors.append('email:password_protected_archive')
        # Also detect if password appears in body via 'password:' keys (heuristic for malicious delivery)
        if meta.get('provided_password'):
            factors.append('email:password_protected_archive')
    except Exception:
        pass
    return factors


# ---------------- Authentication checks (Phase 4) ----------------
def spf_softfail(headers: dict) -> List[str]:
    factors = []
    try:
        r = headers.get('Received-SPF') or headers.get('Authentication-Results') or ''
        if 'softfail' in r.lower() or 'spf=softfail' in r.lower():
            factors.append('email:spf_softfail')
    except Exception:
        pass
    return factors


def dmarc_quarantine(headers: dict, domain: str) -> List[str]:
    factors = []
    try:
        # Try cache first
        cache_key = f'dmarc:{domain}'
        pol = repcache.get(cache_key)
        if pol is None:
            # perform DNS TXT lookup for _dmarc.domain
            dnsr = _ensure_dns()
            if dnsr is not None:
                try:
                    txts = dnsr.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                    pol = None
                    for t in txts:
                        s = ''.join(t.strings) if hasattr(t, 'strings') else str(t)
                        if 'p=' in s:
                            for part in s.split(';'):
                                if part.strip().startswith('p='):
                                    pol = part.strip().split('=')[1]
                                    break
                    repcache.setk(cache_key, pol)
                except Exception:
                    pol = None
            else:
                pol = None
        if pol and pol.lower() == 'quarantine':
            # If policy says quarantine but message not quarantined (heuristic: header shows dmarc=none/fail)
            ar = headers.get('Authentication-Results') or ''
            if 'dmarc=quarantine' not in ar.lower():
                factors.append('email:dmarc_quarantine')
    except Exception:
        pass
    return factors


def dkim_key_weak(headers: dict) -> List[str]:
    factors = []
    try:
        sig = headers.get('DKIM-Signature') or ''
        # look for 'k=rsa; p=' or 'l=' key length hints; fallback: check selector via DNS
        if 'p=' in sig:
            # can't extract key length without DNS lookup; mark as unknown here
            pass
        else:
            # attempt to parse selector from DKIM-Signature header
            m = re.search(r's=([a-zA-Z0-9_\-]+)', sig)
            d = re.search(r'd=([a-zA-Z0-9.\-]+)', sig)
            if m and d:
                selector = m.group(1)
                domain = d.group(1)
                dnsr = _ensure_dns()
                if dnsr is not None:
                    try:
                        txts = dnsr.resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
                        # look for key length numeric approx by p value length
                        for t in txts:
                            s = ''.join(t.strings) if hasattr(t, 'strings') else str(t)
                            if 'p=' in s:
                                # crude heuristic: length of p base64 indicates key size
                                pval = s.split('p=')[1].strip()
                                if len(pval) < 300:  # very small indicates <2048 likely
                                    factors.append('email:dkim_key_weak')
                    except Exception:
                        pass
    except Exception:
        pass
    return factors


def arc_chain_broken(headers: dict) -> List[str]:
    factors = []
    try:
        if 'ARC-Seal' in headers and 'ARC-Authentication-Results' in headers:
            # naive check: if ARC-Seal present but ARC-Authentication-Results contains 'fail'
            ar = headers.get('ARC-Authentication-Results') or ''
            if 'fail' in ar.lower():
                factors.append('email:arc_chain_broken')
    except Exception:
        pass
    return factors


def build(config: dict = None):
    """Return a lane-like callable compatible with LaneRegistry.run_lanes

    Expected to be called with envelope where envelope.headers and envelope.body exist.
    """
    def run(envelope):
        try:
            # resolve tenant-specific config (VIP names, corporate domains)
            vip = set()
            corp = set()
            try:
                vip = set([_normalize(x) for x in (config or {}).get('vip_names', [])]) if isinstance(config, dict) else set()
                corp = set([_normalize(x) for x in (config or {}).get('corporate_domains', [])]) if isinstance(config, dict) else set()
            except Exception:
                vip = set(); corp = set()
            # env fallbacks
            if not vip:
                vip = _parse_set_env('EMAIL_VIP_NAMES') or VIP_NAMES
            if not corp:
                corp = _parse_set_env('EMAIL_CORPORATE_DOMAINS') or CORPORATE_DOMAINS
            headers = getattr(envelope, 'headers', {}) or {}
            body = getattr(envelope, 'body', '') or ''
            factors = []
            factors.extend(display_name_spoof(headers, body, vip, corp))
            factors.extend(financial_keywords(body))
            factors.extend(urgency_keywords(body))
            factors.extend(reply_to_mismatch(headers))
            factors.extend(sender_spoofed_thread(headers))
            # URL analysis detectors
            factors.extend(url_shortener(body))
            factors.extend(url_ip_address(body))
            factors.extend(url_login_keyword(body))
            factors.extend(url_typosquat(body))
            factors.extend(link_domain_mismatch(body))
            factors.extend(excessive_links(body))
            # Attachment detectors - inspect envelope.event or envelope attributes for attachment metadata
            try:
                evt = getattr(envelope, 'event', {}) or {}
                fn = evt.get('file_name') or getattr(envelope, 'file_name', None)
                at = evt.get('attachment_type') or getattr(envelope, 'attachment_type', None)
                attached_list = evt.get('attachment_list') or getattr(envelope, 'attachment_list', None)
                meta = evt.get('attachment_meta') or getattr(envelope, 'attachment_meta', None)
                factors.extend(double_extension(fn))
                factors.extend(rtlo_filename(fn))
                factors.extend(iso_img_attachment(fn, at))
                factors.extend(executable_in_archive(attached_list))
                factors.extend(password_protected_archive(meta))
            except Exception:
                pass
            # Authentication checks based on headers
            try:
                hdrs = getattr(envelope, 'headers', {}) or {}
                factors.extend(spf_softfail(hdrs))
                # extract sender domain
                sender = hdrs.get('From') or hdrs.get('Sender') or ''
                sdomain = ''
                if '@' in sender:
                    try:
                        sdomain = sender.split('@')[-1].strip().lower()
                    except Exception:
                        sdomain = ''
                if sdomain:
                    factors.extend(dmarc_quarantine(hdrs, sdomain))
                factors.extend(dkim_key_weak(hdrs))
                factors.extend(arc_chain_broken(hdrs))
            except Exception:
                pass
            # DKIM crypto verification signal usage (from pipeline)
            try:
                ev = getattr(envelope, 'event', {}) or {}
                sigs = ev.get('email_signals') if isinstance(ev, dict) else {}
                dk = (sigs or {}).get('dkim_crypto')
                if isinstance(dk, dict):
                    v = dk.get('verified')
                    if v is False:
                        factors.append('email:dkim_crypto_fail')
                        # consult history for flips: if previously valid from same from_address, tag flip
                        try:
                            from src.core.enrichment.dkim_history import get_last_dkim
                            frm = headers.get('From') or ''
                            # extract bare email address
                            if '<' in frm and '>' in frm:
                                addr = frm.split('<',1)[1].split('>')[0].strip()
                            else:
                                addr = frm
                            last = get_last_dkim(addr)
                            # Stricter flip detection: require previous valid AND signing domain changed
                            current_signing = None
                            try:
                                current_signing = (dk.get('signing_domain') or dk.get('signingDomain'))
                            except Exception:
                                current_signing = None
                            if last and last.get('valid') is True and current_signing:
                                last_signing = last.get('signing_domain')
                                if last_signing and last_signing != current_signing:
                                    factors.append('email:dkim_flip')
                        except Exception:
                            pass
                    elif v is True:
                        # optional positive signal; useful for suppressing FPs downstream
                        factors.append('email:dkim_crypto_verified')
                        # record history for positive DKIM
                        try:
                            from src.core.enrichment.dkim_history import record_dkim_result
                            frm = headers.get('From') or ''
                            if '<' in frm and '>' in frm:
                                addr = frm.split('<',1)[1].split('>')[0].strip()
                            else:
                                addr = frm
                            signing_domain = dk.get('signing_domain') or dk.get('signingDomain') or None
                            record_dkim_result(addr, True, signing_domain)
                        except Exception:
                            pass
            except Exception:
                pass
            # Use EvidenceEnvelope.add_emission to attach lane-tagged factors
            if factors:
                try:
                    envelope.add_emission('email_bec', factors, None, 0.0)
                except Exception:
                    # Fallback: directly extend lane_factors if add_emission unavailable
                    try:
                        tagged = [f'email_bec:{f}' for f in factors]
                        envelope.lane_factors.extend(tagged)
                    except Exception:
                        pass
        except Exception:
            pass
    return run
