"""Immutable content-addressed object storage for raw evidence."""

from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .metrics import EVIDENCE_OBJECT_WRITE


class ObjectIntegrityError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class StoredObject:
    sha256: str
    locator: str
    size: int


class LocalImmutableObjectStore:
    """Filesystem adapter with S3-style content keys and write-once semantics."""

    def __init__(self, root: str | os.PathLike[str] | None = None) -> None:
        self.root = Path(root or os.getenv("EVIDENCE_OBJECT_ROOT", "data/evidence-objects")).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def digest_file(source: str | os.PathLike[str]) -> tuple[str, int]:
        digest = hashlib.sha256()
        size = 0
        with open(source, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
        return digest.hexdigest(), size

    def put_file(self, source: str | os.PathLike[str]) -> StoredObject:
        source_path = Path(source).resolve(strict=True)
        sha256, size = self.digest_file(source_path)
        destination = self.root / "sha256" / sha256[:2] / sha256[2:4] / sha256
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            existing_hash, existing_size = self.digest_file(destination)
            if existing_hash != sha256 or existing_size != size:
                raise ObjectIntegrityError(f"immutable object conflict: {sha256}")
        else:
            temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
            shutil.copyfile(source_path, temporary)
            copied_hash, copied_size = self.digest_file(temporary)
            if copied_hash != sha256 or copied_size != size:
                temporary.unlink(missing_ok=True)
                raise ObjectIntegrityError("object changed while being captured")
            try:
                os.link(temporary, destination)
            except FileExistsError:
                pass
            finally:
                temporary.unlink(missing_ok=True)
        return StoredObject(sha256=sha256, locator=f"sha256://{sha256}", size=size)

    def put_bytes(self, payload: bytes) -> StoredObject:
        sha256 = hashlib.sha256(payload).hexdigest()
        destination = self.root / "sha256" / sha256[:2] / sha256[2:4] / sha256
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(destination, "xb") as handle:
                handle.write(payload)
        except FileExistsError:
            existing_hash, existing_size = self.digest_file(destination)
            if existing_hash != sha256 or existing_size != len(payload):
                raise ObjectIntegrityError(f"immutable object conflict: {sha256}") from None
        return StoredObject(sha256=sha256, locator=f"sha256://{sha256}", size=len(payload))


class S3WORMObjectStore:
    """AWS S3 Object Lock adapter using compliance-mode retention."""

    def __init__(self, bucket: str, *, client: Any | None = None, retention_days: int = 365) -> None:
        if not bucket:
            raise ValueError("EVIDENCE_S3_BUCKET is required")
        if retention_days < 1:
            raise ValueError("retention_days must be positive")
        if client is None:
            import boto3

            client = boto3.client("s3")
        self.bucket = bucket
        self.client = client
        self.retention_days = retention_days
        config = self.client.get_object_lock_configuration(Bucket=bucket)
        if config.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") != "Enabled":
            raise ObjectIntegrityError("S3 bucket does not have Object Lock enabled")

    def put_file(
        self,
        source: str | os.PathLike[str],
        *,
        tenant_id: str,
        case_id: str,
        legal_hold: bool = False,
    ) -> StoredObject:
        source_path = Path(source).resolve(strict=True)
        sha256, size = LocalImmutableObjectStore.digest_file(source_path)
        key = f"evidence/{tenant_id}/{case_id}/sha256/{sha256}"
        retain_until = datetime.now(timezone.utc) + timedelta(days=self.retention_days)
        try:
            with open(source_path, "rb") as body:
                params = {
                    "Bucket": self.bucket,
                    "Key": key,
                    "Body": body,
                    "ChecksumSHA256": __import__("base64").b64encode(bytes.fromhex(sha256)).decode("ascii"),
                    "ObjectLockMode": "COMPLIANCE",
                    "ObjectLockRetainUntilDate": retain_until,
                    "Metadata": {"sha256": sha256, "tenant-id": tenant_id, "case-id": case_id},
                }
                if legal_hold:
                    params["ObjectLockLegalHoldStatus"] = "ON"
                self.client.put_object(**params)
            EVIDENCE_OBJECT_WRITE.labels("s3-worm", "success").inc()
        except Exception:
            EVIDENCE_OBJECT_WRITE.labels("s3-worm", "failure").inc()
            raise
        return StoredObject(sha256=sha256, locator=f"s3://{self.bucket}/{key}", size=size)

    def put_bytes(self, payload: bytes, *, tenant_id: str, case_id: str, legal_hold: bool = False) -> StoredObject:
        sha256 = hashlib.sha256(payload).hexdigest()
        key = f"evidence/{tenant_id}/{case_id}/sha256/{sha256}"
        retain_until = datetime.now(timezone.utc) + timedelta(days=self.retention_days)
        params = {
            "Bucket": self.bucket,
            "Key": key,
            "Body": payload,
            "ChecksumSHA256": __import__("base64").b64encode(bytes.fromhex(sha256)).decode("ascii"),
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": retain_until,
            "Metadata": {"sha256": sha256, "tenant-id": tenant_id, "case-id": case_id},
        }
        if legal_hold:
            params["ObjectLockLegalHoldStatus"] = "ON"
        self.client.put_object(**params)
        return StoredObject(sha256=sha256, locator=f"s3://{self.bucket}/{key}", size=len(payload))


__all__ = ["LocalImmutableObjectStore", "ObjectIntegrityError", "S3WORMObjectStore", "StoredObject"]
