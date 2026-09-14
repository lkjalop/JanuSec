from __future__ import annotations

import logging
from typing import Dict, Optional

from pydantic import BaseModel

try:
    from email.message import Message as EmailMessage
except Exception:  # pragma: no cover
    EmailMessage = object  # type: ignore

logger = logging.getLogger(__name__)


class EmailAuthResults(BaseModel):
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    alignment_status: Optional[str] = None
    auth_failed: bool = False
    spoof_risk: bool = False


def _canonicalize_token(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    v = value.strip().lower()
    # common variants
    if v in {"pass", "pass (policy)", "policy"}:
        return "pass"
    if v in {"fail", "fail (policy)", "none"}:
        return "fail" if v.startswith("fail") else v
    if v in {"softfail", "temperror", "permerror"}:
        return v
    # default: return lower-cased token (sometimes includes details)
    return v


def parse_authentication_results(header_value: Optional[str]) -> EmailAuthResults:
    """Parse Authentication-Results header into canonical outcomes.

    Tries to extract spf=, dkim=, dmarc= tokens. This is tolerant and
    avoids strict RFC parsing to remain robust across providers.
    """
    res = EmailAuthResults()
    if not header_value:
        return res
    hv = header_value.strip()
    lower = hv.lower()

    def _extract(token: str) -> Optional[str]:
        idx = lower.find(f"{token}=")
        if idx == -1:
            return None
        tail = lower[idx + len(token) + 1 :]
        # token ends at first non-token delimiter
        for stop in [" ", ";", ",", ")", "("]:
            sidx = tail.find(stop)
            if sidx != -1:
                candidate = tail[:sidx]
                return _canonicalize_token(candidate)
        return _canonicalize_token(tail)

    res.spf = _extract("spf")
    res.dkim = _extract("dkim")
    res.dmarc = _extract("dmarc")

    # Derived
    spf_fail = (res.spf or "") == "fail"
    dmarc_fail = (res.dmarc or "") == "fail"
    res.auth_failed = spf_fail or dmarc_fail or ((res.dkim or "") == "fail")

    # Alignment: simplistic heuristic (prefer DMARC)
    if res.dmarc in {"pass", "fail"}:
        res.alignment_status = "aligned" if res.dmarc == "pass" else "fail"
    else:
        # If DMARC missing, infer from SPF+DKIM agreement
        if res.spf == "pass" and res.dkim == "pass":
            res.alignment_status = "aligned"
        elif res.spf == "fail" and res.dkim == "fail":
            res.alignment_status = "fail"
        else:
            res.alignment_status = "partial"

    # Spoof risk: failed auth or missing both DKIM/SPF
    res.spoof_risk = res.auth_failed or (not res.spf and not res.dkim)
    return res


def enrich_email_auth(event) -> None:
    """Attach auth outcomes and derived flags to a NormalizedEmailEvent.

    Works safely with partially populated events.
    """
    try:
        # Prefer Authentication-Results header if present
        auth_header = None
        if isinstance(event.headers, dict):
            # Common header casing variants
            for k in ("Authentication-Results", "authentication-results", "AUTHENTICATION-RESULTS"):
                if k in event.headers:
                    auth_header = event.headers.get(k)
                    break
        results = parse_authentication_results(auth_header)

        # Attach canonical outcomes
        event.spf_result = results.spf
        event.dkim_result = results.dkim
        event.dmarc_result = results.dmarc
        event.auth_failed = results.auth_failed
        event.alignment_status = results.alignment_status
        event.spoof_risk = results.spoof_risk

        # Normalize domains: punycode to IDN-safe forms (best-effort)
        sender = (event.sender or {}).get("email") if isinstance(event.sender, dict) else None
        def _normalize_domain(dom: Optional[str]) -> Optional[str]:
            if not dom:
                return dom
            dom = dom.strip().lower()
            if dom.startswith("xn--"):
                try:
                    import idna  # optional dependency
                    return idna.decode(dom)
                except Exception:
                    return dom
            return dom

        if sender and "@" in sender:
            local, sep, dom = sender.rpartition("@")
            norm_dom = _normalize_domain(dom)
            event.sender = {"email": f"{local}{sep}{norm_dom}"}

        logger.debug("email_auth enrichment applied", extra={
            "spf": event.spf_result,
            "dkim": event.dkim_result,
            "dmarc": event.dmarc_result,
            "auth_failed": event.auth_failed,
            "alignment": event.alignment_status,
            "spoof_risk": event.spoof_risk,
        })
    except Exception as e:  # pragma: no cover
        logger.warning("email_auth enrichment failed: %s", e)
