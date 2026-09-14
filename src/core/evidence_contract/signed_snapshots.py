"""Content-addressed HMAC receipts for IAM, topology, and CMDB snapshots."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import os
from typing import Any, Mapping

from .asymmetric_signing import DigestSigner, cloud_verifier, decode_signature, encode_signature

from .records import canonical_hash

SNAPSHOT_SCHEMA_VERSION = "janusec.infrastructure-snapshot/v1"


def sign_snapshot(*, kind: str, tenant_id: str, payload: Mapping[str, Any], source: str,
                  version: str, valid_from: str, valid_to: str | None = None,
                  key: str | None = None, key_id: str | None = None,
                  signer: DigestSigner | None = None) -> dict[str, Any]:
    secret = key or os.getenv("JANUSEC_SNAPSHOT_HMAC_KEY")
    if not secret and signer is None:
        raise RuntimeError("snapshot_signing_key_not_configured")
    content = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION, "kind": kind, "tenant_id": tenant_id,
        "source": source, "version": version, "valid_from": valid_from, "valid_to": valid_to,
        "payload_hash": canonical_hash(dict(payload)),
    }
    digest = bytes.fromhex(canonical_hash(content))
    if signer is not None:
        signature = encode_signature(signer.sign_digest(digest))
        algorithm = signer.algorithm
        signing_key_id = signer.key_id
    else:
        signature = hmac.new(secret.encode(), canonical_hash(content).encode(), hashlib.sha256).hexdigest()
        algorithm = "hmac-sha256"
        signing_key_id = key_id or os.getenv("JANUSEC_SNAPSHOT_HMAC_KEY_ID", "local")
    return {
        **dict(payload),
        "snapshot_receipt": {
            **content, "signed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "algorithm": algorithm, "key_id": signing_key_id,
            "signature": signature, "receipt_hash": canonical_hash({**content, "signature": signature}),
        },
    }


def verify_snapshot(snapshot: Mapping[str, Any], *, expected_kind: str, tenant_id: str | None = None,
                    key: str | None = None, as_of: dt.datetime | None = None,
                    verifier: DigestSigner | None = None) -> tuple[bool, str]:
    receipt = snapshot.get("snapshot_receipt")
    if not isinstance(receipt, Mapping):
        return False, "snapshot_receipt_missing"
    if receipt.get("kind") != expected_kind:
        return False, "snapshot_kind_mismatch"
    if receipt.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        return False, "snapshot_schema_unsupported"
    algorithm = str(receipt.get("algorithm") or "")
    if algorithm not in {"hmac-sha256", "aws-kms-rsassa-pss-sha256", "azure-key-vault-ps256"}:
        return False, "snapshot_algorithm_unsupported"
    if tenant_id and receipt.get("tenant_id") != tenant_id:
        return False, "snapshot_tenant_mismatch"
    payload = {name: value for name, value in snapshot.items() if name != "snapshot_receipt"}
    if canonical_hash(payload) != receipt.get("payload_hash"):
        return False, "snapshot_payload_hash_mismatch"
    signed_fields = {name: receipt.get(name) for name in (
        "schema_version", "kind", "tenant_id", "source", "version", "valid_from", "valid_to", "payload_hash"
    )}
    if algorithm == "hmac-sha256":
        secret = key or os.getenv("JANUSEC_SNAPSHOT_HMAC_KEY")
        if not secret:
            return False, "snapshot_verification_key_unavailable"
        expected = hmac.new(secret.encode(), canonical_hash(signed_fields).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(receipt.get("signature") or "")):
            return False, "snapshot_signature_invalid"
    else:
        if verifier is None:
            verifier = cloud_verifier(
                algorithm=algorithm, key_id=str(receipt.get("key_id") or ""),
            )
        if verifier is None or verifier.algorithm != algorithm or verifier.key_id != receipt.get("key_id"):
            return False, "snapshot_verification_key_unavailable"
        try:
            valid_signature = verifier.verify_digest(
                bytes.fromhex(canonical_hash(signed_fields)),
                decode_signature(str(receipt.get("signature") or "")),
            )
        except Exception:
            return False, "snapshot_signature_invalid"
        if not valid_signature:
            return False, "snapshot_signature_invalid"
    now = as_of or dt.datetime.now(dt.timezone.utc)
    try:
        valid_from = dt.datetime.fromisoformat(str(receipt["valid_from"]).replace("Z", "+00:00"))
        valid_from = valid_from if valid_from.tzinfo else valid_from.replace(tzinfo=dt.timezone.utc)
        if valid_from > now:
            return False, "snapshot_not_yet_valid"
    except (KeyError, TypeError, ValueError):
        return False, "snapshot_validity_invalid"
    if receipt.get("valid_to"):
        try:
            expiry = dt.datetime.fromisoformat(str(receipt["valid_to"]).replace("Z", "+00:00"))
            expiry = expiry if expiry.tzinfo else expiry.replace(tzinfo=dt.timezone.utc)
            if expiry <= now:
                return False, "snapshot_stale"
        except ValueError:
            return False, "snapshot_validity_invalid"
    return True, "verified"


__all__ = ["SNAPSHOT_SCHEMA_VERSION", "sign_snapshot", "verify_snapshot"]
