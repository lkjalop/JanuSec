from __future__ import annotations

from typing import Any, Dict, List


def quarantine_similar(ms_graph_client, query: Dict[str, Any]) -> Dict[str, Any]:
    """Bulk quarantine via Microsoft Graph (scaffold)."""
    try:
        count = 0
        messages = ms_graph_client.search_messages(query)
        for m in messages or []:
            ms_graph_client.quarantine_message(m.get("id"))
            count += 1
        return {"status": "ok", "count": count}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def notify_impacted_users(notifier, users: List[str], context: Dict[str, Any]) -> Dict[str, Any]:
    try:
        for u in users:
            notifier.send(u, context)
        return {"status": "ok", "count": len(users)}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def revoke_oauth(identity_client, app_id: str, user_id: str) -> Dict[str, Any]:
    try:
        identity_client.revoke_token(app_id=app_id, user_id=user_id)
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def isolate_host(endpoint_client, host_id: str) -> Dict[str, Any]:
    try:
        endpoint_client.isolate(host_id)
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


__all__ = [
    "quarantine_similar",
    "notify_impacted_users",
    "revoke_oauth",
    "isolate_host",
]
