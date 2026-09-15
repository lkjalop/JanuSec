from src.core.evidence_contract.semantic_adapters import normalize_semantics


def test_azure_and_gcp_identity_resource_semantics_preserve_native_fields():
    azure = normalize_semantics({
        "source_type": "azure", "activityDisplayName": "Add member to role",
        "initiatedBy": {"user": {"userPrincipalName": "alex@example.com"}},
        "targetResources": [{"id": "role-1", "displayName": "Admin"}],
    })
    assert azure["actor_id"] == "alex@example.com" and azure["resource_id"] == "role-1"
    assert azure["targetResources"][0]["displayName"] == "Admin"
    gcp = normalize_semantics({"protoPayload": {
        "methodName": "storage.objects.get", "resourceName": "projects/_/buckets/b/objects/x",
        "authenticationInfo": {"principalEmail": "svc@p.iam.gserviceaccount.com", "serviceAccountDelegationInfo": [
            {"firstPartyPrincipal": {"principalEmail": "human@example.com"}}
        ]},
    }})
    assert gcp["actor_type"] == "service_account"
    assert gcp["delegated_by"] == ["human@example.com"]
    assert gcp["action_direction"] == "resource_to_principal"


def test_alibaba_put_is_not_exfil_and_email_forwarding_is_directional():
    ali = normalize_semantics({
        "service": "Alibaba OSS", "eventName": "OSSPutObject", "result": "success",
        "userIdentity": {"principalId": "ram:alice"}, "object_key": "archive.zip",
    })
    assert ali["actor_id"] == "ram:alice"
    assert ali["action_direction"] == "principal_to_resource"
    assert "attack_milestone" not in ali
    mail = normalize_semantics({"source_type": "email", "Operation": "New-InboxRule", "UserId": "victim@example.com", "ForwardTo": "drop@evil.test"})
    assert mail["action_direction"] == "mailbox_to_forward_destination"
    assert mail["destination"] == "drop@evil.test"


def test_email_externality_is_derived_from_sender_and_recipient_domains():
    from src.core.evidence_contract.semantic_adapters import normalize_semantics

    sent = normalize_semantics({
        "_source_type": "email",
        "UserId": "analyst@corp.example",
        "event_name": "MessageSent",
        "Recipients": ["archive@outside.example"],
        "AttachmentCount": 2,
    })
    internal = normalize_semantics({
        "_source_type": "email",
        "UserId": "analyst@corp.example",
        "event_name": "MessageSent",
        "Recipients": ["peer@corp.example"],
        "AttachmentCount": 2,
    })
    assert sent["external_recipient_domain"] == "outside.example"
    assert sent["action_direction"] == "mailbox_to_external_recipient"
    assert "external_recipient_domain" not in internal


def test_microsoft_365_result_status_promotes_common_outcome():
    downloaded = normalize_semantics({
        "_source_type": "email",
        "Operation": "FileDownloaded",
        "UserId": "analyst@corp.example",
        "ObjectId": "/sites/legal/terms.pdf",
        "ResultStatus": "Succeeded",
    })
    denied = normalize_semantics({
        "_source_type": "email",
        "Operation": "FileDownloaded",
        "UserId": "analyst@corp.example",
        "ObjectId": "/sites/legal/terms.pdf",
        "ResultStatus": "AccessDenied",
    })
    assert downloaded["action_outcome"] == "success"
    assert downloaded["action_direction"] == "resource_to_principal"
    assert denied["action_outcome"] == "denied"


def test_network_endpoint_ebpf_and_management_plane_semantics():
    suricata = normalize_semantics({"source_type": "suricata", "event_type": "alert", "src_ip": "10.0.0.1", "dest_ip": "8.8.8.8", "alert": {"action": "blocked"}})
    assert suricata["action_outcome"] == "denied" and suricata["dst_ip"] == "8.8.8.8"
    sysmon = normalize_semantics({"source_type": "sysmon", "EventID": 1, "Image": "powershell.exe", "ParentImage": "cmd.exe"})
    assert sysmon["action_direction"] == "parent_to_child" and sysmon["sysmon_activity"] == "process_create"
    ebpf = normalize_semantics({"source_type": "ebpf", "syscall": "openat", "comm": "cat", "path": "/etc/shadow", "pid": 3, "ppid": 2})
    assert ebpf["ebpf_object_type"] == "file" and ebpf["resource_id"] == "/etc/shadow"
    vmware = normalize_semantics({"source_type": "vmware vcenter", "operation": "ReconfigureVM", "user": "ops", "vm": "db01", "status": "success"})
    assert vmware["semantic_family"] == "management_plane" and vmware["action_direction"] == "principal_to_resource"


def test_sysmon_process_identity_and_file_direction_are_preserved():
    row = normalize_semantics({
        "source_type": "sysmon", "EventID": 11, "Computer": "db-01",
        "Image": "C:\\Windows\\powershell.exe", "ProcessId": "4242",
        "TargetFilename": "C:\\staging\\archive.zip",
    })
    assert row["host"] == "db-01"
    assert row["process_id"] == "4242"
    assert row["resource_id"].endswith("archive.zip")
    assert row["action_direction"] == "process_to_resource"


def test_ebpf_socket_lineage_is_directional():
    row = normalize_semantics({
        "source_type": "ebpf", "syscall": "connect", "comm": "curl", "pid": 9,
        "ppid": 2, "node_name": "k8s-1", "daddr": "203.0.113.8",
    })
    assert row["process_id"] == 9
    assert row["parent_process_id"] == 2
    assert row["host"] == "k8s-1"
    assert row["dst_ip"] == "203.0.113.8"
    assert row["action_direction"] == "process_to_destination"


def test_provider_native_firewall_sysmon_ebpf_and_management_shapes():
    pan = normalize_semantics({
        "vendor": "Palo Alto PAN-OS firewall", "type": "TRAFFIC", "src": "10.1.2.3",
        "dst": "198.51.100.7", "action": "deny",
    })
    assert (pan["src_ip"], pan["dst_ip"], pan["action_outcome"]) == ("10.1.2.3", "198.51.100.7", "denied")
    sysmon = normalize_semantics({
        "Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 3,
        "EventData": {"Image": "curl.exe", "ProcessId": "91", "DestinationIp": "203.0.113.9"},
    })
    assert sysmon["process"] == "curl.exe" and sysmon["dst_ip"] == "203.0.113.9"
    tetragon = normalize_semantics({
        "source_type": "eBPF Tetragon", "syscall": "execve",
        "process": {"binary": "/bin/sh", "pid": 22}, "parent": {"pid": 7},
    })
    assert tetragon["process"] == "/bin/sh" and tetragon["parent_process_id"] == 7
    for source, payload, expected in (
        ("Nutanix Prism", {"userName": "admin", "entityId": "vm-17"}, "vm-17"),
        ("VMware vCenter", {"userName": "ops", "objectName": "db-vm"}, "db-vm"),
        ("HPE OneView", {"userName": "infra", "resourceName": "frame-3"}, "frame-3"),
    ):
        item = normalize_semantics({"source_type": source, "operation": "update", **payload})
        assert item["semantic_family"] == "management_plane"
        assert item["resource_id"] == expected
