"""Offline file-store key rotation. Never prints keys or token payloads.

Stop all users of the file store before calling rotate_file_store. A marker
blocks new backend instances if a process dies during the multi-file commit.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil

from cryptography.fernet import Fernet


def rotate_file_store(store: Path, backup: Path) -> dict:
    store, backup = store.resolve(), backup.resolve()
    if backup == store or store in backup.parents:
        raise ValueError("Recovery directory must be outside the tenant store")
    marker = store / ".rotation-in-progress"
    if marker.exists():
        raise RuntimeError("Interrupted rotation: restore the recovery copy before retrying")
    key_path = store / "fernet.key"
    old_key = key_path.read_bytes()
    old = Fernet(old_key)
    paths = sorted(store.glob("*.json.enc"))
    # Authenticate every ciphertext before making any change.
    plaintext = {p.name: old.decrypt(p.read_bytes()) for p in paths}
    new_key = Fernet.generate_key()
    new = Fernet(new_key)
    encrypted = {name: new.encrypt(value) for name, value in plaintext.items()}
    backup.mkdir(parents=True, exist_ok=False, mode=0o700)
    for p in [key_path, *paths]:
        shutil.copy2(p, backup / p.name)
        os.chmod(backup / p.name, 0o600)
    marker.write_text("Offline key rotation in progress; recovery required if interrupted.\n")
    try:
        for name, value in {**encrypted, "fernet.key": new_key}.items():
            temporary = store / (name + ".rotation-new")
            with temporary.open("xb") as fh:
                os.chmod(temporary, 0o600)
                fh.write(value)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(temporary, store / name)
        for name, expected in plaintext.items():
            if new.decrypt((store / name).read_bytes()) != expected:
                raise RuntimeError("Rotated ciphertext verification failed")
    except Exception:
        # Restore all original files, retaining marker if restoration fails.
        for p in [key_path, *paths]:
            shutil.copy2(backup / p.name, p)
        for name in [*encrypted, "fernet.key"]:
            (store / (name + ".rotation-new")).unlink(missing_ok=True)
        marker.unlink()
        raise
    marker.unlink()
    result = {"schema_version": 1, "encrypted_files": len(paths),
              "payloads_preserved": True, "key_changed": new_key != old_key,
              "new_key_sha256": hashlib.sha256(new_key).hexdigest(),
              "provider_credentials_revoked": False}
    (backup / "receipt.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
