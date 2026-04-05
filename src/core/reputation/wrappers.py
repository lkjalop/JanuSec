from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Callable
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from functools import wraps
from src.core.reputation import cache as repcache

# Simple reputation wrappers used by email lane and tests.
# Network calls are performed lazily and can be monkeypatched in tests.

FREE_PROVIDER_DOMAINS = {
    'gmail.com', 'google.com', 'hotmail.com', 'yahoo.com', 'outlook.com', 'live.com', 'icloud.com'
}

# Circuit-breaker defaults
CB_FAILURE_THRESHOLD = int(__import__('os').getenv('REPUTATION_CB_FAILURES', '3'))
CB_RESET_SECONDS = int(__import__('os').getenv('REPUTATION_CB_RESET_SECONDS', '60'))
DEFAULT_TIMEOUT = float(__import__('os').getenv('REPUTATION_OP_TIMEOUT', '5.0'))
DEFAULT_RETRIES = int(__import__('os').getenv('REPUTATION_RETRIES', '2'))


def _call_with_timeout(func: Callable, timeout: float, *args, **kwargs):
    use_threads = __import__('os').getenv('REPUTATION_USE_THREADS','0').lower() in {'1','true','yes'}
    if not use_threads:
        return func(*args, **kwargs)
    # run in thread to enforce timeout
    with ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(func, *args, **kwargs)
        try:
            return fut.result(timeout=timeout)
        except FutureTimeout:
            try:
                fut.cancel()
            except Exception:
                pass
            raise TimeoutError('operation timed out')


def _cb_get_state(key: str) -> Optional[dict]:
    st = repcache.get(f'cb:{key}')
    return st


def _cb_set_state(key: str, state: dict):
    repcache.setk(f'cb:{key}', state)


def _with_retries_and_cb(cb_key: str, func: Callable, timeout: float = DEFAULT_TIMEOUT, retries: int = DEFAULT_RETRIES, *args, **kwargs):
    # circuit breaker: store {'failures': int, 'opened_at': ts or None}
    st = _cb_get_state(cb_key) or {'failures': 0, 'opened_at': None}
    if st.get('opened_at'):
        if time.time() - st['opened_at'] < CB_RESET_SECONDS:
            # circuit open
            raise RuntimeError('circuit_open')
        else:
            # reset after cooldown
            st = {'failures': 0, 'opened_at': None}
    last_exc = None
    for attempt in range(0, retries + 1):
        try:
            res = _call_with_timeout(func, timeout, *args, **kwargs)
            # success -> reset failure count
            st = {'failures': 0, 'opened_at': None}
            _cb_set_state(cb_key, st)
            return res
        except Exception as exc:
            last_exc = exc
            # increment failure counter
            st['failures'] = st.get('failures', 0) + 1
            if st['failures'] >= CB_FAILURE_THRESHOLD:
                st['opened_at'] = time.time()
            _cb_set_state(cb_key, st)
            # backoff sleep small
            time.sleep(0.1 * (attempt + 1))
            continue
    # all retries failed
    raise last_exc


def _perform_whois(domain: str) -> Optional[Dict[str, Any]]:
    try:
        import whois as _whois
        res = _whois.whois(domain)
        return {'creation_date': getattr(res, 'creation_date', None), 'registrar': getattr(res, 'registrar', None)}
    except Exception:
        return None


def _perform_mx_lookup(domain: str) -> List[str]:
    try:
        import dns.resolver as _dr
        answers = []
        try:
            for r in _dr.resolve(domain, 'MX', lifetime=DEFAULT_TIMEOUT):
                try:
                    answers.append(str(r.exchange).rstrip('.').lower())
                except Exception:
                    answers.append(str(r).lower())
        except Exception:
            pass
        return answers
    except Exception:
        return []


def _perform_geoip(ip: str) -> Optional[Dict[str, Any]]:
    try:
        import geoip2.database as _gdb
        # Expect environment var GEOIP_DB_PATH for production use
        dbp = __import__('os').getenv('GEOIP_DB_PATH')
        if not dbp:
            return None
        with _gdb.Reader(dbp) as rdr:
            try:
                rec = rdr.city(ip)
                return {'country': getattr(rec.country, 'iso_code', None), 'city': getattr(rec.city, 'name', None)}
            except Exception:
                return None
    except Exception:
        return None


def whois_domain_age_days(domain: str, *, cache_ttl: int = None) -> Optional[int]:
    key = f'whois_age:{domain}'
    v = repcache.get(key)
    if v is not None:
        return v
    try:
        info = _with_retries_and_cb(f'whois:{domain}', _perform_whois, DEFAULT_TIMEOUT, DEFAULT_RETRIES, domain)
    except Exception:
        info = None
    age = None
    try:
        if info and info.get('creation_date'):
            cd = info.get('creation_date')
            if isinstance(cd, list):
                cd = cd[0]
            if isinstance(cd, datetime):
                age = int((time.time() - cd.timestamp()) / 86400)
            else:
                try:
                    cdp = datetime.fromisoformat(str(cd))
                    age = int((time.time() - cdp.timestamp()) / 86400)
                except Exception:
                    age = None
    except Exception:
        age = None
    repcache.setk(key, age)
    return age


def mx_providers_for_domain(domain: str) -> List[str]:
    key = f'mx:{domain}'
    v = repcache.get(key)
    if v is not None:
        return v
    try:
        mxs = _with_retries_and_cb(f'mx:{domain}', _perform_mx_lookup, DEFAULT_TIMEOUT, DEFAULT_RETRIES, domain)
    except Exception:
        mxs = []
    repcache.setk(key, mxs)
    return mxs


def mx_is_free_provider(domain: str) -> bool:
    try:
        mxs = mx_providers_for_domain(domain)
        for m in mxs:
            for p in FREE_PROVIDER_DOMAINS:
                if p in m:
                    return True
        dom = domain.lower()
        if dom in FREE_PROVIDER_DOMAINS:
            return True
    except Exception:
        pass
    return False


def geoip_lookup(ip: str) -> Optional[Dict[str, Any]]:
    key = f'geoip:{ip}'
    v = repcache.get(key)
    if v is not None:
        return v
    try:
        info = _with_retries_and_cb(f'geoip:{ip}', _perform_geoip, DEFAULT_TIMEOUT, DEFAULT_RETRIES, ip)
    except Exception:
        info = None
    repcache.setk(key, info)
    return info
