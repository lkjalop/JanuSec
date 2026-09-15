"""Provider-neutral connectors for signed IAM, topology, and CMDB snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .records import canonical_hash
from .signed_snapshots import sign_snapshot
from .asymmetric_signing import DigestSigner


SnapshotFetcher = Callable[[], Mapping[str, Any]]
_KINDS = {
    "iam", "topology", "cmdb", "data_classification",
    "regulatory_applicability", "control_verification",
}


def _pair(value: Any, left: str, right: str) -> list[str] | None:
    if isinstance(value, (list, tuple)) and len(value) == 2:
        return [str(value[0]), str(value[1])]
    if isinstance(value, Mapping) and value.get(left) and value.get(right):
        return [str(value[left]), str(value[right])]
    return None


def normalize_snapshot_payload(kind: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the minimum provider-neutral sandbox contract.

    Native provider fields remain in ``provider_native``; only explicit links
    are normalized.  The collector never infers reachability, authorization or
    business impact from names, tags or shared identifiers.
    """

    result = dict(payload)
    if kind == "iam":
        candidates = payload.get("allowed_paths") or payload.get("authorization_paths") or []
        paths = [pair for item in candidates if (pair := _pair(item, "principal", "resource"))]
        if not paths:
            raise ValueError("iam_snapshot_requires_explicit_authorization_paths")
        result["allowed_paths"] = paths
    elif kind == "topology":
        allowed = [pair for item in payload.get("allowed_routes") or [] if (pair := _pair(item, "source", "target"))]
        denied = [pair for item in payload.get("denied_routes") or [] if (pair := _pair(item, "source", "target"))]
        if not allowed and not denied:
            raise ValueError("topology_snapshot_requires_explicit_routes")
        result["allowed_routes"], result["denied_routes"] = allowed, denied
    elif kind == "cmdb":
        mappings = []
        services: dict[str, dict[str, Any]] = {}
        for item in payload.get("asset_service_mappings") or []:
            pair = _pair(item, "asset_id", "service_id")
            if not pair:
                continue
            mappings.append(pair)
            if isinstance(item, Mapping):
                service = item.get("service")
                if isinstance(service, Mapping):
                    service_id = str(service.get("id") or pair[1])
                    services[service_id] = {**dict(service), "id": service_id}
        for service in payload.get("business_services") or []:
            if isinstance(service, Mapping) and (service.get("id") or service.get("name")):
                service_id = str(service.get("id") or service.get("name"))
                services[service_id] = {**dict(service), "id": service_id}
        if not mappings:
            raise ValueError("cmdb_snapshot_requires_explicit_asset_service_mappings")
        normalized_services = [services[key] for key in sorted(services)]
        result["asset_service_mappings"] = mappings
        result["business_services"] = normalized_services
        result["mapped_services_hash"] = canonical_hash(normalized_services)
    elif kind == "data_classification":
        classifications = []
        for item in payload.get("asset_classifications") or []:
            if not isinstance(item, Mapping) or not item.get("asset_id") or not item.get("classification"):
                continue
            classifications.append({
                **dict(item), "asset_id": str(item["asset_id"]),
                "classification": str(item["classification"]),
                "data_categories": sorted(str(value) for value in item.get("data_categories") or [] if value),
            })
        if not classifications:
            raise ValueError("data_classification_requires_explicit_asset_classifications")
        result["asset_classifications"] = classifications
        result["classification_mapping_hash"] = canonical_hash(classifications)
    elif kind == "regulatory_applicability":
        allowed = {"applicable", "not_applicable", "review_required"}
        obligations = []
        for item in payload.get("obligations") or []:
            if not isinstance(item, Mapping):
                continue
            status = str(item.get("applicability_status") or "")
            if not all((item.get("obligation_id"), item.get("authority"), item.get("jurisdiction"), item.get("version"))) or status not in allowed:
                continue
            scope = item.get("applicable_to") if isinstance(item.get("applicable_to"), Mapping) else {}
            if not any(scope.get(key) for key in ("asset_ids", "service_ids", "data_categories")):
                continue
            obligations.append({**dict(item), "applicability_status": status, "applicable_to": dict(scope)})
        if not obligations:
            raise ValueError("regulatory_applicability_requires_versioned_scoped_obligations")
        result["obligations"] = obligations
        result["applicability_mapping_hash"] = canonical_hash(obligations)
    return result


@dataclass(frozen=True, slots=True)
class SignedSnapshotConnector:
    kind: str
    source: str
    fetcher: SnapshotFetcher

    def collect(self, *, tenant_id: str, version: str, valid_from: str,
                valid_to: str | None = None, key: str | None = None,
                key_id: str | None = None,
                signer: DigestSigner | None = None) -> dict[str, Any]:
        if self.kind not in _KINDS:
            raise ValueError("unsupported_snapshot_kind")
        payload = self.fetcher()
        if not isinstance(payload, Mapping):
            raise TypeError("snapshot_fetcher_must_return_mapping")
        if not payload:
            raise ValueError("empty_snapshot_rejected")
        payload = normalize_snapshot_payload(self.kind, payload)
        return sign_snapshot(
            kind=self.kind, tenant_id=tenant_id, payload=payload, source=self.source,
            version=version, valid_from=valid_from, valid_to=valid_to, key=key,
            key_id=key_id, signer=signer,
        )


def collect_sandbox_infrastructure_truth(
    *, tenant_id: str, version: str, valid_from: str, valid_to: str,
    iam: Mapping[str, Any], topology: Mapping[str, Any], cmdb: Mapping[str, Any],
    key: str | None = None, key_id: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Collect a complete, signed sandbox truth bundle for acceptance tests."""

    inputs = {"iam": iam, "topology": topology, "cmdb": cmdb}
    return {
        kind: SignedSnapshotConnector(
            kind=kind, source=f"sandbox/{kind}/v1", fetcher=lambda value=value: value,
        ).collect(
            tenant_id=tenant_id, version=version, valid_from=valid_from,
            valid_to=valid_to, key=key, key_id=key_id,
        )
        for kind, value in inputs.items()
    }


__all__ = [
    "SignedSnapshotConnector", "SnapshotFetcher", "collect_sandbox_infrastructure_truth",
    "normalize_snapshot_payload",
]
