"""
Confluence Push — v1 Secondary Integration
==========================================

Pushes the assembled PostmortemDocument to a Confluence page in the
customer's existing IR runbook space. Used by customers who treat Confluence
as the system-of-record for incident postmortems.

Creates ONE page per postmortem. If a page with the same JanuSec postmortem
ID already exists, updates it (Confluence pages have version chains, so
the bitemporal trace is preserved on Confluence's side too).

CONTENT
-------
The Confluence page renders the full postmortem with the same 7 sections
as the JanuSec UI. Each section's content is the computed view (auto +
overrides applied).

AUTH
----
Same auth model as Jira — basic_auth with email + API token (Atlassian
Cloud) or bearer_token (Server with PAT).
"""
from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

try:
    import requests
except ImportError:
    requests = None


def push(
    *,
    document: dict,
    config: dict,
    dry_run: bool = False,
) -> dict:
    base_url = config.get("base_url", "").rstrip("/")
    space_key = config.get("space_key") or config.get("space")
    parent_page_id = config.get("parent_page_id")  # optional

    if not base_url or not space_key:
        return {"success": False, "error": "confluence config missing base_url or space_key"}

    page_payload = _build_page_payload(document, space_key, parent_page_id)

    if dry_run:
        return {
            "success": True,
            "dry_run": True,
            "page_payload": page_payload,
            "would_call":   f"{base_url}/wiki/rest/api/content",
        }

    if requests is None:
        return {"success": False, "error": "requests not available"}

    auth = _build_auth_handle(config.get("auth") or {})
    if auth is None:
        return {"success": False, "error": "confluence auth not configured"}

    # Check if a page with the same JanuSec postmortem ID already exists,
    # so we update rather than create duplicates.
    existing = _find_existing_page(base_url, space_key, document.get("postmortem_id"), auth)
    if existing:
        return _update_page(base_url, existing, page_payload, auth)
    return _create_page(base_url, page_payload, auth)


# ─────────────────────────────────────────────────────────────────────────────
#  Content building
# ─────────────────────────────────────────────────────────────────────────────


def _build_page_payload(document: dict, space_key: str, parent_page_id: Optional[str]) -> dict:
    cluster_id = document.get("cluster_id", "?")
    verdict = (document.get("verdict") or {}).get("platform_verdict", "?")
    pm_id = document.get("postmortem_id", "?")

    title = f"JanuSec Postmortem: {cluster_id} — {verdict} [{pm_id}]"
    body_html = _render_storage_format(document)

    payload: dict[str, Any] = {
        "type":  "page",
        "title": title,
        "space": {"key": space_key},
        "body": {
            "storage": {
                "value":          body_html,
                "representation": "storage",
            }
        },
        "metadata": {
            "labels": [
                {"prefix": "global", "name": "janusec"},
                {"prefix": "global", "name": "postmortem"},
                {"prefix": "global", "name": pm_id},
            ],
        },
    }
    if parent_page_id:
        payload["ancestors"] = [{"id": parent_page_id}]
    return payload


def _render_storage_format(document: dict) -> str:
    """Render the postmortem to Confluence storage-format XHTML."""
    from src.postmortem.postmortem_assembler import get_computed_section

    pm_id = document.get("postmortem_id", "?")
    cluster_id = document.get("cluster_id", "?")
    verdict = document.get("verdict") or {}

    parts: list[str] = []
    parts.append(f"<p><strong>Postmortem ID:</strong> {pm_id}</p>")
    parts.append(f"<p><strong>Cluster:</strong> {cluster_id}</p>")
    parts.append(
        f"<p><strong>Verdict:</strong> {verdict.get('platform_verdict','?')} "
        f"(confidence {verdict.get('confidence', 0.0):.2f})</p>"
    )
    parts.append(f"<p><strong>Materiality:</strong> {verdict.get('materiality_assessment','?')}</p>")
    parts.append(_warning_panel(
        "JanuSec NEVER auto-submits to a regulator. All regulatory notification "
        "drafts shown here require human review and submission via the regulator's "
        "official channel."
    ))

    section_titles = {
        "s1_incident_lifecycle":     "1. Incident Lifecycle (ISO 27035)",
        "s2_threat_reconstruction":  "2. Threat Reconstruction (MITRE + STRIDE)",
        "s3_control_failures":       "3. Control Failures by Framework",
        "s4_sabsa_architecture":     "4. SABSA Architecture & Policy Implications",
        "s5_risk_register_delta":    "5. Risk Register Delta",
        "s6_regulatory_clocks":      "6. Regulatory Notification Clocks",
        "s7_corrective_actions":     "7. Corrective Actions",
    }

    for sec in (document.get("sections") or []):
        sid = sec.get("section_id")
        title = section_titles.get(sid, sid)
        parts.append(f"<h2>{_escape(title)}</h2>")
        v1_status = sec.get("v1_status")
        if v1_status == "STUB":
            parts.append(_info_panel(f"This section is a v1 stub. Available in v2."))
        computed = get_computed_section(document, sid) if sid else None
        if computed is None:
            parts.append("<p><em>(no content)</em></p>")
            continue
        parts.append(f"<pre>{_escape(_pretty_json(computed))}</pre>")

    parts.append("<h2>Provenance</h2>")
    ev = document.get("evidence_provenance") or {}
    parts.append(f"<p>Evidence rows: {ev.get('row_count', 0)}; "
                 f"hash: <code>{ev.get('evidence_content_hash','?')}</code></p>")

    return "".join(parts)


def _warning_panel(text: str) -> str:
    return (f'<ac:structured-macro ac:name="warning"><ac:rich-text-body>'
            f'<p>{_escape(text)}</p></ac:rich-text-body></ac:structured-macro>')


def _info_panel(text: str) -> str:
    return (f'<ac:structured-macro ac:name="info"><ac:rich-text-body>'
            f'<p>{_escape(text)}</p></ac:rich-text-body></ac:structured-macro>')


def _escape(s: str) -> str:
    if s is None:
        return ""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                  .replace(">", "&gt;").replace('"', "&quot;"))


def _pretty_json(obj: Any) -> str:
    import json
    try:
        return json.dumps(obj, indent=2, default=str)
    except Exception:
        return str(obj)


# ─────────────────────────────────────────────────────────────────────────────
#  HTTP helpers
# ─────────────────────────────────────────────────────────────────────────────


def _build_auth_handle(auth_config: dict):
    method = (auth_config.get("method") or "").lower()
    if method == "basic_auth":
        email = auth_config.get("email") or ""
        token = auth_config.get("api_token") or ""
        if not email or not token or requests is None:
            return None
        return requests.auth.HTTPBasicAuth(email, token)
    if method == "bearer_token":
        token = auth_config.get("token") or ""
        return ("__bearer__", token) if token else None
    return None


def _find_existing_page(base_url: str, space_key: str, pm_id: str, auth) -> Optional[dict]:
    """CQL search for a page with the postmortem ID label."""
    if requests is None or not pm_id:
        return None
    url = f"{base_url}/wiki/rest/api/content/search"
    params = {
        "cql": f'space = "{space_key}" and label = "{pm_id}"',
        "limit": 1,
    }
    try:
        headers = {"Accept": "application/json"}
        if isinstance(auth, tuple) and auth[0] == "__bearer__":
            headers["Authorization"] = f"Bearer {auth[1]}"
            r = requests.get(url, params=params, headers=headers, timeout=30)
        else:
            r = requests.get(url, params=params, headers=headers, auth=auth, timeout=30)
        if r.status_code != 200:
            return None
        results = (r.json() or {}).get("results") or []
        return results[0] if results else None
    except Exception as exc:
        logger.warning("confluence search failed: %s", exc)
        return None


def _create_page(base_url: str, payload: dict, auth) -> dict:
    if requests is None:
        return {"success": False, "error": "requests not available"}
    url = f"{base_url}/wiki/rest/api/content"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    try:
        if isinstance(auth, tuple) and auth[0] == "__bearer__":
            headers["Authorization"] = f"Bearer {auth[1]}"
            r = requests.post(url, json=payload, headers=headers, timeout=30)
        else:
            r = requests.post(url, json=payload, headers=headers, auth=auth, timeout=30)
        if r.status_code in (200, 201):
            data = r.json() or {}
            return {
                "success":  True,
                "page_id":  data.get("id"),
                "page_url": (data.get("_links") or {}).get("base", "") + (data.get("_links") or {}).get("webui", ""),
            }
        return {"success": False, "error": f"confluence_http_{r.status_code}", "body": r.text[:500]}
    except Exception as exc:
        return {"success": False, "error": f"confluence_exception:{exc}"}


def _update_page(base_url: str, existing: dict, payload: dict, auth) -> dict:
    if requests is None:
        return {"success": False, "error": "requests not available"}
    page_id = existing.get("id")
    current_version = ((existing.get("version") or {}).get("number") or 1)
    payload = {
        **payload,
        "version": {"number": current_version + 1},
    }
    url = f"{base_url}/wiki/rest/api/content/{page_id}"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    try:
        if isinstance(auth, tuple) and auth[0] == "__bearer__":
            headers["Authorization"] = f"Bearer {auth[1]}"
            r = requests.put(url, json=payload, headers=headers, timeout=30)
        else:
            r = requests.put(url, json=payload, headers=headers, auth=auth, timeout=30)
        if r.status_code in (200, 201):
            data = r.json() or {}
            return {
                "success":  True,
                "page_id":  data.get("id"),
                "version":  ((data.get("version") or {}).get("number")),
                "updated":  True,
            }
        return {"success": False, "error": f"confluence_http_{r.status_code}", "body": r.text[:500]}
    except Exception as exc:
        return {"success": False, "error": f"confluence_exception:{exc}"}


__all__ = ["push"]
