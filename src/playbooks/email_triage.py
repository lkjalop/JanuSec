from typing import List, Dict, Any
import logging
from src.connectors.email.ms_graph import MSGraphConnector
import requests

logger = logging.getLogger(__name__)


class EmailTriagePlaybook:
    def __init__(self, graph_connector: MSGraphConnector, soar_base: str = None, soar_api_key: str = None):
        self.graph = graph_connector
        self.soar_base = soar_base
        self.soar_api_key = soar_api_key

    def expand_iocs(self, iocs: Dict[str, Any]) -> Dict[str, Any]:
        """Expand IOCs with derived fields useful for Graph queries.

        Example expansions:
        - `url_host` taken from a provided `url`
        - `sender` normalized to lowercase
        - `subject` trimmed
        - `url_fingerprint` simple sha256 of url string
        """
        import hashlib, urllib.parse
        out = dict(iocs or {})
        if out.get("url"):
            try:
                p = urllib.parse.urlparse(out.get("url"))
                out["url_host"] = p.netloc.lower()
                out["url_fingerprint"] = hashlib.sha256(out.get("url").encode("utf-8")).hexdigest()
            except Exception:
                pass
        if out.get("sender"):
            out["sender"] = out.get("sender").lower()
        if out.get("subject"):
            out["subject"] = (out.get("subject") or "").strip()
        return out

    def _call_soar_revoke(self, user_id: str, reason: str = "suspicious_email") -> Dict[str, Any]:
        if not self.soar_base:
            return {"status": "noop", "reason": "no-soar-config"}
        url = f"{self.soar_base}/api/v1/soar/remediate/iam/revoke_token"
        headers = {"Content-Type": "application/json"}
        if self.soar_api_key:
            headers["x-api-key"] = self.soar_api_key
        body = {"user_id": user_id, "reason": reason}
        try:
            r = requests.post(url, json=body, headers=headers, timeout=5)
            return r.json()
        except Exception as e:
            logger.exception("soar call failed")
            return {"status": "error", "error": str(e)}

    def bulk_search_and_quarantine(self, tenant: str, iocs: Dict[str, Any], reason: str = "phish") -> Dict[str, Any]:
        # Expand IOCs for better search coverage
        iocs_expanded = self.expand_iocs(iocs)
        parts = []
        if iocs_expanded.get("sender"):
            parts.append(f"from:{iocs_expanded['sender']}")
        if iocs_expanded.get("subject"):
            parts.append(f"subject:\"{iocs_expanded['subject']}\"")
        if iocs_expanded.get("url_host"):
            parts.append(f"body:{iocs_expanded['url_host']}")
        if iocs_expanded.get("url_fingerprint"):
            # Some gateways store URL hashes in message metadata; include when present
            parts.append(f"body:{iocs_expanded['url_fingerprint']}")
        query = " AND ".join(parts) if parts else ""
        msgs = self.graph.search_similar_messages(tenant, query)
        ids = [m.get("id") for m in msgs]
        # detect display-name vs envelope-from mismatch (basic heuristic)
        mismatch_users = []
        for m in msgs:
            frm = (m.get('from') or '')
            if '<' in frm and '>' in frm:
                # display-name <addr>
                try:
                    addr = frm.split('<')[-1].split('>')[0].strip().lower()
                    display = frm.split('<')[0].strip().strip('"')
                    if display and addr and display.lower() not in addr:
                        mismatch_users.append(addr)
                except Exception:
                    pass

        dry_run = bool(iocs.get('dry_run'))
        if ids and not dry_run:
            res = self.graph.quarantine_messages(tenant, ids, reason=reason)
        else:
            res = {"quarantined": 0, "dry_run": True, "count": len(ids)}

        return {"query": query, "found": len(ids), "mismatch_users": mismatch_users, "quarantine_result": res}
