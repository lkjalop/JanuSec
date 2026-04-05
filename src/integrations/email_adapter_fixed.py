from typing import Dict, Any, List, Optional
from .email_transports import BaseTransport
from .email_checks import redact_pii, dkim_check, spf_check, dmarc_evaluate, compute_sha256_hex


class EmailAdapter:
    def __init__(self, transport: BaseTransport):
        self.transport = transport

    def fetch_and_canonicalize(self, since: Optional[int] = None) -> List[Dict[str, Any]]:
        msgs = self.transport.list_messages(since=since)
        out: List[Dict[str, Any]] = []
        for m in msgs:
            out.append(self.canonicalize_message(m))
        return out

    def canonicalize_message(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        body = raw.get("body", "")
        redacted = redact_pii(body)
        try:
            body_hash = compute_sha256_hex(redacted.encode("utf-8"))
        except Exception:
            body_hash = compute_sha256_hex(redacted)

        headers = raw.get("headers") or {}
        dkim = dkim_check(headers)
        spf = spf_check(raw.get("from", ""), raw.get("return_path", raw.get("from", "")))
        dmarc = dmarc_evaluate(raw.get("from", ""), dkim, spf)

        return {
            "id": raw.get("id"),
            "ts": raw.get("ts"),
            "from": raw.get("from"),
            "to": raw.get("to"),
            "subject": raw.get("subject"),
            "body_redacted": redacted,
            "body_hash": body_hash,
            "dkim": dkim,
            "spf": spf,
            "dmarc": dmarc,
            "raw": raw,
        }
