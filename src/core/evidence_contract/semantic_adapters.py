"""Source-specific semantic adapters over the provider-neutral evidence contract.

Adapters add OCSF-aligned activity/actor/resource/outcome fields while preserving
every provider-native field in the returned row.
"""

from __future__ import annotations

from typing import Any

from .directionality import apply_directionality


def _nested(value: Any, *path: str) -> Any:
    current = value
    for part in path:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _first(*values: Any) -> Any:
    return next((value for value in values if value not in (None, "", [], {})), None)


def _family(row: dict[str, Any]) -> str:
    source = str(_first(row.get("source_type"), row.get("_source_type"), row.get("vendor"), row.get("provider"), row.get("service"), "")).lower()
    text = " ".join(str(_first(row.get(key), "")) for key in ("eventSource", "serviceName", "channel", "log_type")).lower()
    if "suricata" in source + text or row.get("event_type") in {"alert", "flow", "dns", "http", "tls"}:
        return "suricata"
    if "sysmon" in source + text or str(row.get("Channel") or "").lower().endswith("sysmon/operational"):
        return "sysmon"
    if "ebpf" in source + text or row.get("syscall"):
        return "ebpf"
    if "firewall" in source + text or "pan-os" in source + text or "forti" in source + text:
        return "firewall"
    if "azure" in source + text or row.get("initiatedBy") or row.get("targetResources"):
        return "azure"
    if "gcp" in source + text or row.get("protoPayload"):
        return "gcp"
    if any(token in source + text for token in ("alibaba", "aliyun", "oss.")):
        return "alibaba"
    if any(token in source + text for token in ("exchange", "email", "mail", "m365")) or row.get("ForwardTo"):
        return "email"
    if any(token in source + text for token in ("nutanix", "vmware", "vcenter", "esxi", "hpe", "oneview", "ilo")):
        return "management_plane"
    return "generic"


def normalize_semantics(original: dict[str, Any]) -> dict[str, Any]:
    row = dict(original)
    family = _family(row)
    row["semantic_family"] = family

    if family == "azure":
        initiated = row.get("initiatedBy") if isinstance(row.get("initiatedBy"), dict) else {}
        actor = _first(
            _nested(initiated, "user", "userPrincipalName"), _nested(initiated, "user", "id"),
            _nested(initiated, "app", "displayName"), _nested(initiated, "app", "servicePrincipalId"),
            row.get("identity"), row.get("caller"),
        )
        targets = row.get("targetResources") if isinstance(row.get("targetResources"), list) else []
        target = targets[0] if targets and isinstance(targets[0], dict) else {}
        row.setdefault("actor_id", actor)
        row.setdefault("actor_type", "service_principal" if _nested(initiated, "app") else "user")
        row.setdefault("resource_id", _first(target.get("id"), target.get("displayName"), row.get("resourceId")))
        row.setdefault("resource_type", _first(target.get("type"), row.get("resourceType"), "azure_resource"))
        row.setdefault("operationName", _first(row.get("operationName"), row.get("activityDisplayName")))
    elif family == "gcp":
        proto = row.get("protoPayload") if isinstance(row.get("protoPayload"), dict) else {}
        auth = proto.get("authenticationInfo") if isinstance(proto.get("authenticationInfo"), dict) else {}
        delegates = auth.get("serviceAccountDelegationInfo") if isinstance(auth.get("serviceAccountDelegationInfo"), list) else []
        row.setdefault("actor_id", _first(auth.get("principalEmail"), row.get("principalEmail")))
        row.setdefault("actor_type", "service_account" if "gserviceaccount.com" in str(row.get("actor_id") or "") else "user")
        row.setdefault("delegated_by", [
            _first(_nested(item, "firstPartyPrincipal", "principalEmail"), _nested(item, "principalSubject"))
            for item in delegates if isinstance(item, dict)
        ])
        row.setdefault("resource_id", _first(proto.get("resourceName"), _nested(proto, "resource", "name")))
        row.setdefault("resource_type", _first(_nested(proto, "resource", "type"), row.get("resource_type"), "gcp_resource"))
        row.setdefault("methodName", _first(proto.get("methodName"), row.get("methodName")))
        if proto.get("status"):
            row.setdefault("outcome", "failure" if _nested(proto, "status", "code") else "success")
    elif family == "alibaba":
        identity = row.get("userIdentity") if isinstance(row.get("userIdentity"), dict) else {}
        request = row.get("requestParameters") if isinstance(row.get("requestParameters"), dict) else {}
        row.setdefault("actor_id", _first(identity.get("principalId"), identity.get("userName"), row.get("userName")))
        row.setdefault("actor_type", _first(identity.get("type"), "ram_principal"))
        row.setdefault("resource_id", _first(
            row.get("resourceName"), row.get("object_key"), request.get("key"), request.get("objectName"),
            request.get("bucketName"),
        ))
        row.setdefault("resource_type", _first(row.get("resourceType"), "alibaba_resource"))
        row.setdefault("cloud_provider", "alibaba")
    elif family == "email":
        row.setdefault("actor_id", _first(row.get("SenderFromAddress"), row.get("sender"), row.get("UserId"), row.get("mailbox")))
        row.setdefault("mailbox", _first(row.get("mailbox"), row.get("UserId"), row.get("recipient")))
        row.setdefault("forward_to", _first(
            row.get("ForwardTo"), row.get("ForwardingSmtpAddress"),
            row.get("forwarding_smtp"), row.get("RedirectTo"),
        ))
        row.setdefault("destination", _first(row.get("forward_to"), row.get("external_recipient"), row.get("recipient")))
        recipients = _first(row.get("Recipients"), row.get("recipients"), row.get("To"), row.get("to"), [])
        if isinstance(recipients, str):
            recipients = [recipients]
        if not isinstance(recipients, list):
            recipients = []
        origin = str(_first(row.get("actor_id"), row.get("mailbox"), ""))
        origin_domain = origin.rsplit("@", 1)[-1].lower() if "@" in origin else ""
        external = next(
            (
                str(value)
                for value in recipients
                if "@" in str(value)
                and origin_domain
                and str(value).rsplit("@", 1)[-1].lower() != origin_domain
            ),
            None,
        )
        destination = str(_first(row.get("forward_to"), external, ""))
        if destination and "@" in destination:
            destination_domain = destination.rsplit("@", 1)[-1].lower()
            if not origin_domain or destination_domain != origin_domain:
                row.setdefault("external_recipient_domain", destination_domain)
                row.setdefault("destination", destination)
        action = "".join(ch for ch in str(_first(row.get("event_name"), row.get("action"), "")).lower() if ch.isalnum())
        if external and action in {"send", "messagesent", "sendmessage"}:
            row.setdefault("action_direction", "mailbox_to_external_recipient")
    elif family in {"firewall", "suricata"}:
        flow = row.get("flow") if isinstance(row.get("flow"), dict) else {}
        row.setdefault("src_ip", _first(row.get("src_ip"), row.get("src"), flow.get("src_ip"), row.get("source_ip")))
        row.setdefault("dst_ip", _first(row.get("dest_ip"), row.get("dst_ip"), row.get("dst"), flow.get("dest_ip"), row.get("destination_ip")))
        disposition = str(_first(row.get("action"), row.get("verdict"), _nested(row, "alert", "action"), "")).lower()
        if disposition:
            row.setdefault("outcome", "denied" if disposition in {"block", "blocked", "deny", "denied", "drop", "dropped"} else "success")
        row.setdefault("network_direction", _first(row.get("direction"), flow.get("direction"), "source_to_destination"))
    elif family == "sysmon":
        data = row.get("EventData") if isinstance(row.get("EventData"), dict) else {}
        event_id = str(_first(row.get("EventID"), row.get("event_id"), data.get("EventID"), ""))
        row.setdefault("process", _first(row.get("Image"), data.get("Image"), row.get("process_name"), row.get("process")))
        row.setdefault("parent_process", _first(row.get("ParentImage"), data.get("ParentImage"), row.get("parent_process")))
        row.setdefault("process_id", _first(row.get("ProcessId"), data.get("ProcessId"), row.get("process_id"), row.get("pid")))
        row.setdefault("parent_process_id", _first(row.get("ParentProcessId"), data.get("ParentProcessId"), row.get("parent_process_id"), row.get("ppid")))
        row.setdefault("host", _first(row.get("Computer"), data.get("Computer"), row.get("hostname"), row.get("host")))
        row.setdefault("src_ip", _first(row.get("SourceIp"), data.get("SourceIp"), row.get("src_ip")))
        row.setdefault("dst_ip", _first(row.get("DestinationIp"), data.get("DestinationIp"), row.get("dst_ip")))
        row.setdefault("resource_id", _first(row.get("TargetFilename"), data.get("TargetFilename"), row.get("target_file")))
        if event_id == "1":
            row.setdefault("action_direction", "parent_to_child")
        elif event_id == "3":
            row.setdefault("action_direction", "process_to_destination")
        elif event_id == "11":
            row.setdefault("action_direction", "process_to_resource")
        row.setdefault("sysmon_activity", {"1": "process_create", "3": "network_connect", "11": "file_create"}.get(event_id, "other"))
    elif family == "ebpf":
        process = row.get("process") if isinstance(row.get("process"), dict) else {}
        parent = row.get("parent") if isinstance(row.get("parent"), dict) else {}
        syscall = str(row.get("syscall") or "").lower()
        row.setdefault("activity_name", syscall)
        row["process"] = _first(row.get("comm"), process.get("binary"), process.get("name"), row.get("exe"))
        row.setdefault("process_id", _first(row.get("pid"), process.get("pid"), row.get("process_id")))
        row.setdefault("parent_process_id", _first(row.get("ppid"), parent.get("pid"), process.get("parent_pid"), row.get("parent_pid")))
        row.setdefault("host", _first(row.get("node_name"), row.get("hostname"), row.get("host")))
        row.setdefault("src_ip", _first(row.get("saddr"), row.get("src_ip"), row.get("source_ip")))
        row.setdefault("dst_ip", _first(row.get("daddr"), row.get("dst_ip"), row.get("destination_ip")))
        row.setdefault("resource_id", _first(row.get("path"), row.get("filename"), row.get("socket")))
        row.setdefault("ebpf_object_type", "socket" if syscall in {"connect", "accept", "bind"} else "file" if syscall in {"open", "openat", "read", "write"} else "process")
        if syscall in {"execve", "clone", "fork", "vfork"}:
            row.setdefault("action_direction", "parent_to_child")
        elif syscall in {"connect", "sendto", "sendmsg"}:
            row.setdefault("action_direction", "process_to_destination")
        elif syscall in {"open", "openat", "read", "write", "unlink", "rename"}:
            row.setdefault("action_direction", "process_to_resource")
    elif family == "management_plane":
        row.setdefault("actor_id", _first(row.get("user"), row.get("userName"), row.get("username"), row.get("principal"), row.get("actor")))
        row.setdefault("resource_id", _first(
            row.get("object"), row.get("objectName"), row.get("entity"), row.get("entityId"),
            row.get("vm"), row.get("host"), row.get("resource"), row.get("resourceName"),
        ))
        row.setdefault("action_direction", "principal_to_resource")
        row.setdefault("outcome", _first(row.get("result"), row.get("status"), "unknown"))

    # Common OCSF-like subject/object fields. These do not discard native data
    # and deliberately avoid resolving identity on weak identifiers.
    row.setdefault("actor_id", _first(row.get("principal_id"), row.get("user_canonical"), row.get("user"), row.get("username"), row.get("actor")))
    row.setdefault("host", _first(row.get("hostname"), row.get("Computer"), row.get("device_name"), row.get("host")))
    row.setdefault("process_id", _first(row.get("pid"), row.get("ProcessId"), row.get("process_id")))
    row.setdefault("parent_process_id", _first(row.get("ppid"), row.get("ParentProcessId"), row.get("parent_process_id")))

    row.setdefault("activity_name", _first(row.get("action_name"), row.get("eventName"), row.get("operationName"), row.get("Operation"), row.get("methodName"), row.get("event_type")))
    if row.get("actor_id") and not row.get("user_canonical"):
        row["user_canonical"] = row["actor_id"]
    return apply_directionality(row)


__all__ = ["normalize_semantics"]
