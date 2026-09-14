"""Cloud-backed asymmetric signers for infrastructure snapshot receipts."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Protocol


class DigestSigner(Protocol):
    algorithm: str
    key_id: str

    def sign_digest(self, digest: bytes) -> bytes: ...
    def verify_digest(self, digest: bytes, signature: bytes) -> bool: ...


@dataclass(slots=True)
class AWSKMSSigner:
    key_id: str
    client: Any
    signing_algorithm: str = "RSASSA_PSS_SHA_256"
    algorithm: str = "aws-kms-rsassa-pss-sha256"

    def sign_digest(self, digest: bytes) -> bytes:
        response = self.client.sign(
            KeyId=self.key_id, Message=digest, MessageType="DIGEST",
            SigningAlgorithm=self.signing_algorithm,
        )
        return bytes(response["Signature"])

    def verify_digest(self, digest: bytes, signature: bytes) -> bool:
        response = self.client.verify(
            KeyId=self.key_id, Message=digest, MessageType="DIGEST",
            Signature=signature, SigningAlgorithm=self.signing_algorithm,
        )
        return bool(response.get("SignatureValid"))


@dataclass(slots=True)
class AzureKeyVaultSigner:
    key_id: str
    client: Any
    signature_algorithm: Any = "PS256"
    algorithm: str = "azure-key-vault-ps256"

    def sign_digest(self, digest: bytes) -> bytes:
        result = self.client.sign(self.signature_algorithm, digest)
        return bytes(result.signature)

    def verify_digest(self, digest: bytes, signature: bytes) -> bool:
        result = self.client.verify(self.signature_algorithm, digest, signature)
        return bool(result.is_valid)


def encode_signature(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def decode_signature(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def cloud_verifier(*, algorithm: str, key_id: str) -> DigestSigner | None:
    """Construct a verifier from ambient cloud identity; never falls back to HMAC."""

    if algorithm == "aws-kms-rsassa-pss-sha256":
        try:
            import boto3

            return AWSKMSSigner(key_id=key_id, client=boto3.client("kms"))
        except Exception:
            return None
    if algorithm == "azure-key-vault-ps256":
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm

            return AzureKeyVaultSigner(
                key_id=key_id,
                client=CryptographyClient(key_id, DefaultAzureCredential()),
                signature_algorithm=SignatureAlgorithm.ps256,
            )
        except Exception:
            return None
    return None


__all__ = [
    "AWSKMSSigner", "AzureKeyVaultSigner", "DigestSigner",
    "cloud_verifier", "decode_signature", "encode_signature",
]
