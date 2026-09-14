from src.core.evidence_contract.directionality import apply_directionality


def test_cloudtrail_get_and_put_have_opposite_directions_and_denial_is_preserved():
    get = apply_directionality({"eventName": "GetObject", "_result": "SUCCESS", "requestParameters": {"key": "x"}})
    put = apply_directionality({"eventName": "PutObject", "_result": "SUCCESS", "requestParameters": {"key": "x"}})
    denied = apply_directionality({"eventName": "GetObject", "errorCode": "AccessDenied"})
    assert get["action_direction"] == "resource_to_principal" and get["data_access"] == "read"
    assert put["action_direction"] == "principal_to_resource" and put["data_access"] == "write"
    assert denied["action_outcome"] == "denied"


def test_network_and_endpoint_directionality_are_not_interpreted_as_cloud_reads():
    flow = apply_directionality({"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8"})
    proc = apply_directionality({"parent_process": "cmd.exe", "process": "powershell.exe"})
    assert flow["action_direction"] == "source_to_destination"
    assert proc["action_direction"] == "parent_to_child"


def test_cloud_collection_is_provider_neutral_and_denials_are_not_milestones():
    cases = [
        ({"eventName": "GetObject", "eventSource": "s3.amazonaws.com", "_result": "SUCCESS"}, "aws"),
        ({"operation": "GetBlob", "service": "Azure Blob Storage", "result": "Succeeded"}, "azure"),
        ({"methodName": "storage.objects.get", "result": "success"}, "gcp"),
        ({"eventName": "OSSGetObject", "service": "Alibaba OSS", "result": "success"}, "alibaba"),
        ({"Operation": "FileDownloaded", "service": "SharePoint", "result": "success"}, "microsoft_365"),
    ]
    for raw, provider in cases:
        row = apply_directionality(raw)
        assert row["cloud_provider"] == provider
        assert row["action_direction"] == "resource_to_principal"
        assert row["attack_milestone"] == "cloud_object_collection"
        assert "sharepoint_bulk_download" in row["milestone_compatibility_aliases"]
    denied = apply_directionality({"eventName": "GetObject", "eventSource": "s3.amazonaws.com", "errorCode": "AccessDenied"})
    assert denied["action_outcome"] == "denied"
    assert "attack_milestone" not in denied
