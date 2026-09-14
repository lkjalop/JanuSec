"""Offline, encrypted backups of a complete isolated pilot state directory.

The pilot launcher and backup share an OS lock. Backups require a stopped service;
restore only creates a new directory and authenticates the archive before writing
its files. The independent backup key must be retained outside the state directory.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile
import zipfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b'JANUSEC-PILOT-BACKUP-1\n'
CHUNK = 1024 * 1024
MANIFEST = 'backup-manifest.json'


@contextmanager
def state_lock(root: Path):
    root = root.resolve(strict=True)
    if (root / '.restore-in-progress').exists():
        raise RuntimeError('incomplete_restore: restore into a new directory before serving')
    lock_path = root / '.janusec-state.lock'
    if lock_path.is_symlink() or lock_path.resolve() != lock_path.absolute():
        raise ValueError('unsafe_state_lock_path')
    handle = lock_path.open('a+b')
    try:
        handle.seek(0)
        if os.name == 'nt':
            import msvcrt
            if os.fstat(handle.fileno()).st_size == 0:
                handle.write(b'0'); handle.flush()
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                raise RuntimeError('pilot_state_busy: stop the service before backup') from None
        else:
            import fcntl
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise RuntimeError('pilot_state_busy: stop the service before backup') from None
        yield
    finally:
        handle.close()  # OS releases the lock even after a process crash.


def _digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _key(path: Path) -> bytes:
    value = path.read_bytes()
    if len(value) != 32:
        raise ValueError('backup_key_must_be_32_random_bytes')
    return value


def _state_files(root: Path):
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name
            if path.is_symlink() or path.resolve() != path.absolute():
                raise ValueError('backup_rejects_symlinks_or_junctions')
        for name in sorted(files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if relative == '.janusec-state.lock':
                continue
            if relative == MANIFEST or not path.is_file():
                raise ValueError('unsupported_state_file')
            yield relative, path


def backup(root: Path, destination: Path, key_file: Path) -> dict:
    root = root.resolve(strict=True)
    destination = destination.resolve()
    key_file = key_file.resolve(strict=True)
    if destination.is_relative_to(root) or key_file.is_relative_to(root):
        raise ValueError('backup_and_recovery_key_must_be_outside_state')
    secret = _key(key_file)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError('backup_destination_already_exists')
    with state_lock(root), tempfile.TemporaryFile(dir=destination.parent) as plain:
        inventory = {}
        with zipfile.ZipFile(plain, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for relative, path in _state_files(root):
                inventory[relative] = {'sha256': _digest(path), 'bytes': path.stat().st_size}
                archive.write(path, relative)
            archive.writestr(MANIFEST, json.dumps({'schema': 1, 'files': inventory}, sort_keys=True))
        plain.seek(0)
        nonce = os.urandom(12)
        encryptor = Cipher(algorithms.AES(secret), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(MAGIC)
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, 'wb') as output:
                output.write(MAGIC + nonce)
                while block := plain.read(CHUNK):
                    output.write(encryptor.update(block))
                output.write(encryptor.finalize())
                output.write(encryptor.tag)
                output.flush(); os.fsync(output.fileno())
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
    return {'files': len(inventory), 'bytes': destination.stat().st_size,
            'sha256': _digest(destination), 'mode': 'offline-encrypted-complete-state'}


def restore(archive_path: Path, destination: Path, key_file: Path) -> dict:
    destination = destination.resolve()
    if destination.exists():
        raise FileExistsError('restore_requires_a_new_destination')
    destination.parent.mkdir(parents=True, exist_ok=True)
    secret = _key(key_file)
    with archive_path.open('rb') as source, tempfile.TemporaryFile(dir=destination.parent) as plain:
        if source.read(len(MAGIC)) != MAGIC:
            raise ValueError('invalid_backup_format')
        nonce = source.read(12)
        source.seek(-16, 2)
        tag = source.read(16)
        remaining = source.tell() - len(MAGIC) - 12 - 16
        source.seek(len(MAGIC) + 12)
        decryptor = Cipher(algorithms.AES(secret), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(MAGIC)
        while remaining > 0:
            block = source.read(min(CHUNK, remaining))
            if not block:
                raise ValueError('truncated_backup')
            plain.write(decryptor.update(block))
            remaining -= len(block)
        plain.write(decryptor.finalize())  # Authentication must succeed before extraction.
        plain.seek(0)
        with zipfile.ZipFile(plain) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise ValueError('duplicate_backup_members')
            manifest = json.loads(archive.read(MANIFEST))
            if manifest.get('schema') != 1 or set(names) != set(manifest['files']) | {MANIFEST}:
                raise ValueError('invalid_backup_inventory')
            for name, expected in manifest['files'].items():
                parts = PurePosixPath(name).parts
                if (not parts or PurePosixPath(name).is_absolute() or '\\' in name
                        or ':' in name or any(p in {'.', '..'} or p.endswith(('.', ' ')) for p in parts)
                        or name in {'.janusec-state.lock', '.restore-in-progress'}):
                    raise ValueError('unsafe_backup_member')
                info = archive.getinfo(name)
                if info.is_dir() or stat.S_ISLNK(info.external_attr >> 16):
                    raise ValueError('unsupported_backup_member')
                digest = hashlib.sha256()
                size = 0
                with archive.open(name) as item:
                    while block := item.read(CHUNK):
                        digest.update(block); size += len(block)
                if size != expected['bytes'] or digest.hexdigest() != expected['sha256']:
                    raise ValueError('backup_member_integrity_failed')
            destination.mkdir(mode=0o700)
            marker = destination / '.restore-in-progress'
            marker.write_text('Restore has not completed; do not start this state.', encoding='utf-8')
            for name in manifest['files']:
                target = destination.joinpath(*PurePosixPath(name).parts)
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with archive.open(name) as item, target.open('xb') as output:
                    os.chmod(target, 0o600)
                    while block := item.read(CHUNK):
                        output.write(block)
                    output.flush(); os.fsync(output.fileno())
            marker.unlink()
    return {'files': len(manifest['files']), 'verified': True, 'mode': 'new-directory-restore'}
