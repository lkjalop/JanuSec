"""Provider-neutral action direction, outcome, role, and milestone enrichment."""

from __future__ import annotations

from typing import Any


_READ_ACTIONS = {
    "getobject", "downloadobject", "filedownloaded", "fileaccessed", "read", "download",
    "storageobjectsget", "getblob", "blobdownloaded", "ossgetobject",
}
_WRITE_ACTIONS = {
    "putobject", "uploadobject", "fileuploaded", "write", "upload",
    "storageobjectscreate", "storageobjectsinsert", "putblob", "ossputobject",
}
_DENIED_RESULTS = {
    "denied", "accessdenied", "permissiondenied", "blocked", "failure",
    "failed", "forbidden", "unauthorized",
}
_SUCCESS_RESULTS = {"success", "succeeded", "allowed", "ok", "completed"}

CLOUD_COLLECTION_MILESTONE = "cloud_object_collection"
CLOUD_COLLECTION_COMPATIBILITY_ALIASES = ("sharepoint_bulk_download",)


def _fold(value: Any) -> str:
    return "".join(ch for ch in str(value or "").lower() if ch.isalnum())


def _provider(row: dict[str, Any], folded_action: str) -> str | None:
    explicit = str(row.get("cloud_provider") or row.get("provider") or "").strip().lower()
    if explicit:
        aliases = {"amazon": "aws", "amazon web services": "aws", "microsoft": "azure", "aliyun": "alibaba"}
        return aliases.get(explicit, explicit)
    service = str(row.get("eventSource") or row.get("serviceName") or row.get("service") or "").lower()
    if "amazonaws" in service or row.get("awsRegion"):
        return "aws"
    if "storage.objects" in str(row.get("methodName") or row.get("method_name") or "") or folded_action.startswith("storageobjects"):
        return "gcp"
    if "sharepoint" in service or folded_action == "filedownloaded":
        return "microsoft_365"
    if "blob" in folded_action or "azure" in service:
        return "azure"
    if "oss" in service or folded_action.startswith("oss"):
        return "alibaba"
    return None


def apply_directionality(row: dict[str, Any]) -> dict[str, Any]:
    action = str(
        row.get("eventName")
        or row.get("operationName")
        or row.get("Operation")
        or row.get("operation")
        or row.get("event_name")
        or row.get("action")
        or row.get("methodName")
        or row.get("method_name")
        or ""
    ).strip()
    folded = _fold(action)
    # Providers spell the same disposition differently.  Keep the native
    # field, but promote it into one common outcome used by causal thresholds.
    # In particular, Microsoft 365 audit rows use ``ResultStatus``; treating
    # those successful operations as unknown made a confirmed access path look
    # weaker than the evidence actually supports.
    result = _fold(
        row.get("_result")
        or row.get("outcome")
        or row.get("result")
        or row.get("ResultStatus")
        or row.get("resultStatus")
        or row.get("status")
        or ""
    )
    status_code = str(row.get("status_code") or row.get("http_status") or "")
    denied = bool(row.get("errorCode") or row.get("error_code")) or result in _DENIED_RESULTS or status_code.startswith(("4", "5"))
    row.setdefault("action_name", action or None)
    row.setdefault("action_outcome", "denied" if denied else "success" if result in _SUCCESS_RESULTS else "unknown")
    provider = _provider(row, folded)
    if provider:
        row.setdefault("cloud_provider", provider)

    if folded in _READ_ACTIONS:
        row.setdefault("action_direction", "resource_to_principal")
        row.setdefault("data_access", "read")
        if not denied:
            row.setdefault("attack_milestone", CLOUD_COLLECTION_MILESTONE)
            row.setdefault("milestone_compatibility_aliases", list(CLOUD_COLLECTION_COMPATIBILITY_ALIASES))
    elif folded in _WRITE_ACTIONS:
        row.setdefault("action_direction", "principal_to_resource")
        row.setdefault("data_access", "write")
    elif row.get("src_ip") and row.get("dst_ip"):
        row.setdefault("action_direction", "source_to_destination")
    elif row.get("parent_process") or row.get("parent_image"):
        row.setdefault("action_direction", "parent_to_child")

    params = row.get("requestParameters") if isinstance(row.get("requestParameters"), dict) else {}
    resource = (
        row.get("resource_id") or row.get("resourceName") or row.get("resource_name")
        or row.get("object_key") or row.get("blob_name") or params.get("key") or params.get("bucketName")
    )
    if resource:
        row.setdefault("target_resource", resource)
    if folded.startswith(("newinboxrule", "setinboxrule")) or row.get("forward_to"):
        row.setdefault("action_direction", "mailbox_to_forward_destination")
        row.setdefault("destination", row.get("forward_to") or row.get("ForwardTo"))
    return row


__all__ = [
    "CLOUD_COLLECTION_COMPATIBILITY_ALIASES",
    "CLOUD_COLLECTION_MILESTONE",
    "apply_directionality",
]
