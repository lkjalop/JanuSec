"""Offline certificate installation with an atomic active-version pointer."""
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import secrets
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from src.backup.pilot_state import state_lock


def tls_paths(state: Path):
    pointer = state / 'tls.json'
    if not pointer.exists():
        return state / 'tls-cert.pem', state / 'tls-key.pem'
    version = json.loads(pointer.read_text(encoding='utf-8'))['version']
    if not isinstance(version, str) or len(version) != 32 or any(c not in '0123456789abcdef' for c in version):
        raise ValueError('invalid_tls_version')
    root = state / 'tls' / version
    if not root.resolve().is_relative_to(state.resolve()):
        raise ValueError('tls_path_escape')
    return root / 'cert.pem', root / 'key.pem'


def install(state: Path, cert_path: Path, key_path: Path, hostname: str, *, local_test=False):
    state = state.resolve(strict=True)
    cert_bytes, key_bytes = cert_path.read_bytes(), key_path.read_bytes()
    certificate = x509.load_pem_x509_certificate(cert_bytes)
    key = serialization.load_pem_private_key(key_bytes, password=None)
    encode = lambda public: public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if encode(key.public_key()) != encode(certificate.public_key()):
        raise ValueError('certificate_key_mismatch')
    now = datetime.now(timezone.utc)
    if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
        raise ValueError('certificate_not_current')
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    try:
        matched = ipaddress.ip_address(hostname) in san.get_values_for_type(x509.IPAddress)
    except ValueError:
        matched = hostname.lower() in [name.lower() for name in san.get_values_for_type(x509.DNSName)]
    if not matched:
        raise ValueError('certificate_hostname_mismatch')
    if certificate.subject == certificate.issuer and not (local_test and hostname in {'localhost', '127.0.0.1'}):
        raise ValueError('customer_certificate_must_be_issued_by_a_ca')
    # Validate the supplied PEM chain/key pair without exposing key material.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with state_lock(state):
        version = secrets.token_hex(16)
        root = state / 'tls' / version
        root.mkdir(parents=True, mode=0o700)
        for name, value in [('cert.pem', cert_bytes), ('key.pem', key_bytes)]:
            fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(value); stream.flush(); os.fsync(stream.fileno())
        context.load_cert_chain(str(root / 'cert.pem'), str(root / 'key.pem'))
        temp = state / ('tls-' + version + '.tmp')
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                json.dump({'version': version, 'hostname': hostname}, stream)
                stream.flush(); os.fsync(stream.fileno())
            os.replace(temp, state / 'tls.json')
        finally:
            temp.unlink(missing_ok=True)
    return {'installed': True, 'hostname': hostname, 'expires_at': certificate.not_valid_after_utc.isoformat(),
            'client_trust_and_renewal_still_require_validation': True}
