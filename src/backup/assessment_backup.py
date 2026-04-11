"""Assessment backup — nightly copy of data/assessments/ to S3, Azure Blob, or local archive.

Environment variables
---------------------
BACKUP_ENABLED          : '1'|'true'|'yes' to activate (default off for safety)
BACKUP_DEST             : 's3', 'azure', or 'local' (default: local)
BACKUP_SCHEDULE_HOUR    : UTC hour to run (default: 2)
BACKUP_RETENTION_DAYS   : How many days of backups to keep (default: 30)
BACKUP_LOCAL_DIR        : Path for local archives (default: data/backups)

S3 variables (BACKUP_DEST=s3):
  BACKUP_S3_BUCKET      : Target S3 bucket name (required)
  BACKUP_S3_PREFIX      : Key prefix (default: janusec/assessments)
  BACKUP_S3_REGION      : AWS region (falls back to AWS_REGION)
  BACKUP_ROLE_ARN       : IAM role ARN to assume for upload (optional)

Azure variables (BACKUP_DEST=azure):
  BACKUP_AZURE_ACCOUNT  : Storage account name (required)
  BACKUP_AZURE_CONTAINER: Container name (default: janusec-backups)
  BACKUP_AZURE_SAS_URL  : Full SAS URL (alternative to account name)
  BACKUP_AZURE_CONN_STR : Connection string (alternative)
"""
from __future__ import annotations

import asyncio
import gzip
import json
import logging
import os
import shutil
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_BACKUP_MANAGER: Optional['AssessmentBackupManager'] = None
_BACKUP_TASK: Optional[asyncio.Task] = None


def _is_enabled() -> bool:
    return os.getenv('BACKUP_ENABLED', '0').lower() in {'1', 'true', 'yes'}


def _assessments_dir() -> Path:
    return Path(os.getenv('ASSESSMENTS_DIR', 'data/assessments'))


def _backup_local_dir() -> Path:
    p = Path(os.getenv('BACKUP_LOCAL_DIR', 'data/backups'))
    p.mkdir(parents=True, exist_ok=True)
    return p


# ---------------------------------------------------------------------------
# Archive builder
# ---------------------------------------------------------------------------

def _build_archive(source_dir: Path, label: str) -> Path:
    """Create a .tar.gz of source_dir in a temp directory. Returns archive path."""
    tmp = Path(tempfile.mkdtemp(prefix='janusec_backup_'))
    archive_name = f"assessments_{label}.tar.gz"
    archive_path = tmp / archive_name
    with tarfile.open(archive_path, 'w:gz') as tf:
        tf.add(source_dir, arcname='assessments')
    logger.info('Backup archive created: %s (%.1f MB)', archive_path, archive_path.stat().st_size / 1_048_576)
    return archive_path


def _cleanup_tmp(path: Path) -> None:
    try:
        shutil.rmtree(path.parent, ignore_errors=True)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Retention pruning
# ---------------------------------------------------------------------------

def _prune_local_backups(local_dir: Path, retention_days: int) -> int:
    cutoff = time.time() - retention_days * 86400
    removed = 0
    for p in local_dir.glob('assessments_*.tar.gz'):
        try:
            if p.stat().st_mtime < cutoff:
                p.unlink()
                removed += 1
        except Exception:
            pass
    return removed


# ---------------------------------------------------------------------------
# S3 upload
# ---------------------------------------------------------------------------

def _upload_s3(archive_path: Path, label: str) -> Dict[str, Any]:
    bucket = os.getenv('BACKUP_S3_BUCKET', '')
    if not bucket:
        return {'ok': False, 'error': 'BACKUP_S3_BUCKET not configured'}
    prefix = os.getenv('BACKUP_S3_PREFIX', 'janusec/assessments').rstrip('/')
    key = f"{prefix}/{archive_path.name}"
    region = os.getenv('BACKUP_S3_REGION') or os.getenv('AWS_REGION')
    role_arn = os.getenv('BACKUP_ROLE_ARN')
    try:
        import boto3  # type: ignore
        session_kwargs: dict = {}
        if role_arn:
            sts = boto3.client('sts', region_name=region)
            creds = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName='janusec-backup',
                DurationSeconds=3600,
            )['Credentials']
            session_kwargs = {
                'aws_access_key_id': creds['AccessKeyId'],
                'aws_secret_access_key': creds['SecretAccessKey'],
                'aws_session_token': creds['SessionToken'],
            }
        s3 = boto3.client('s3', region_name=region, **session_kwargs)
        with open(archive_path, 'rb') as f:
            s3.upload_fileobj(
                f, bucket, key,
                ExtraArgs={
                    'ServerSideEncryption': 'AES256',
                    'StorageClass': os.getenv('BACKUP_S3_STORAGE_CLASS', 'STANDARD_IA'),
                    'Metadata': {
                        'backup-label': label,
                        'platform': 'janusec',
                    },
                },
            )
        url = f"s3://{bucket}/{key}"
        logger.info('Backup uploaded to S3: %s', url)
        return {'ok': True, 'destination': url, 'bytes': archive_path.stat().st_size}
    except Exception as exc:
        logger.error('S3 backup upload failed: %s', exc)
        return {'ok': False, 'error': str(exc)}


# ---------------------------------------------------------------------------
# Azure Blob upload
# ---------------------------------------------------------------------------

def _upload_azure(archive_path: Path, label: str) -> Dict[str, Any]:
    container = os.getenv('BACKUP_AZURE_CONTAINER', 'janusec-backups')
    blob_name = f"assessments/{archive_path.name}"
    conn_str = os.getenv('BACKUP_AZURE_CONN_STR', '')
    sas_url = os.getenv('BACKUP_AZURE_SAS_URL', '')
    account = os.getenv('BACKUP_AZURE_ACCOUNT', '')
    try:
        from azure.storage.blob import BlobServiceClient  # type: ignore
        if conn_str:
            svc = BlobServiceClient.from_connection_string(conn_str)
        elif sas_url:
            svc = BlobServiceClient(account_url=sas_url)
        elif account:
            # Managed identity / DefaultAzureCredential
            from azure.identity import DefaultAzureCredential  # type: ignore
            svc = BlobServiceClient(
                account_url=f"https://{account}.blob.core.windows.net",
                credential=DefaultAzureCredential(),
            )
        else:
            return {'ok': False, 'error': 'No Azure credentials configured (BACKUP_AZURE_CONN_STR, BACKUP_AZURE_SAS_URL, or BACKUP_AZURE_ACCOUNT)'}
        client = svc.get_blob_client(container=container, blob=blob_name)
        with open(archive_path, 'rb') as f:
            client.upload_blob(
                f,
                overwrite=True,
                metadata={'backup_label': label, 'platform': 'janusec'},
            )
        url = f"https://{account or 'storage'}.blob.core.windows.net/{container}/{blob_name}"
        logger.info('Backup uploaded to Azure Blob: %s', url)
        return {'ok': True, 'destination': url, 'bytes': archive_path.stat().st_size}
    except Exception as exc:
        logger.error('Azure Blob backup upload failed: %s', exc)
        return {'ok': False, 'error': str(exc)}


# ---------------------------------------------------------------------------
# Local copy
# ---------------------------------------------------------------------------

def _copy_local(archive_path: Path) -> Dict[str, Any]:
    local_dir = _backup_local_dir()
    dest = local_dir / archive_path.name
    try:
        shutil.copy2(archive_path, dest)
        logger.info('Backup saved locally: %s', dest)
        return {'ok': True, 'destination': str(dest), 'bytes': dest.stat().st_size}
    except Exception as exc:
        logger.error('Local backup copy failed: %s', exc)
        return {'ok': False, 'error': str(exc)}


# ---------------------------------------------------------------------------
# Main backup manager
# ---------------------------------------------------------------------------

class AssessmentBackupManager:
    """Manages nightly assessment data backups."""

    def __init__(self) -> None:
        self.dest = os.getenv('BACKUP_DEST', 'local').lower()
        self.retention_days = int(os.getenv('BACKUP_RETENTION_DAYS', '30'))
        self._last_run: Optional[float] = None
        self._last_result: Optional[Dict[str, Any]] = None

    def run_backup(self) -> Dict[str, Any]:
        """Run a synchronous backup. Call from asyncio via run_in_executor()."""
        start = time.time()
        source = _assessments_dir()
        if not source.exists():
            logger.warning('Assessment directory does not exist: %s', source)
            return {'ok': False, 'error': f'source_dir_missing: {source}', 'ts': start}

        label = datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        archive: Optional[Path] = None
        try:
            archive = _build_archive(source, label)

            if self.dest == 's3':
                result = _upload_s3(archive, label)
            elif self.dest == 'azure':
                result = _upload_azure(archive, label)
            else:
                result = _copy_local(archive)

            # Prune old local backups regardless of dest (local archives always written)
            pruned = _prune_local_backups(_backup_local_dir(), self.retention_days)
            result['pruned_old'] = pruned
            result['label'] = label
            result['elapsed_s'] = round(time.time() - start, 2)

            self._last_run = time.time()
            self._last_result = result
            return result
        except Exception as exc:
            logger.exception('Backup run failed')
            return {'ok': False, 'error': str(exc), 'label': label, 'elapsed_s': round(time.time() - start, 2)}
        finally:
            if archive:
                _cleanup_tmp(archive)

    async def run_backup_async(self) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.run_backup)

    def status(self) -> Dict[str, Any]:
        return {
            'enabled': _is_enabled(),
            'dest': self.dest,
            'retention_days': self.retention_days,
            'last_run_ts': self._last_run,
            'last_run_ago_s': round(time.time() - self._last_run, 1) if self._last_run else None,
            'last_result': self._last_result,
        }


def get_backup_manager() -> AssessmentBackupManager:
    global _BACKUP_MANAGER
    if _BACKUP_MANAGER is None:
        _BACKUP_MANAGER = AssessmentBackupManager()
    return _BACKUP_MANAGER


# ---------------------------------------------------------------------------
# Nightly scheduler
# ---------------------------------------------------------------------------

async def _backup_loop(manager: AssessmentBackupManager, schedule_hour: int) -> None:
    """Background task: wake every hour, fire backup at the configured UTC hour."""
    logger.info('Assessment backup scheduler started (dest=%s, hour=%dZ)', manager.dest, schedule_hour)
    while True:
        try:
            now = datetime.now(tz=timezone.utc)
            if now.hour == schedule_hour and (
                manager._last_run is None or (time.time() - manager._last_run) > 3600
            ):
                logger.info('Starting nightly assessment backup...')
                result = await manager.run_backup_async()
                if result.get('ok'):
                    logger.info('Nightly backup succeeded: %s', result.get('destination'))
                else:
                    logger.error('Nightly backup FAILED: %s', result.get('error'))
        except Exception as exc:
            logger.exception('Backup loop error: %s', exc)
        await asyncio.sleep(3600)


def schedule_nightly_backup() -> None:
    """Start the nightly backup background task. Call once from app startup."""
    global _BACKUP_TASK
    if not _is_enabled():
        logger.debug('Assessment backup disabled (set BACKUP_ENABLED=1 to enable)')
        return
    if _BACKUP_TASK is not None and not _BACKUP_TASK.done():
        return  # Already running
    manager = get_backup_manager()
    schedule_hour = int(os.getenv('BACKUP_SCHEDULE_HOUR', '2'))
    try:
        loop = asyncio.get_event_loop()
        _BACKUP_TASK = loop.create_task(_backup_loop(manager, schedule_hour))
        logger.info('Nightly backup task scheduled (hour=%dZ, dest=%s)', schedule_hour, manager.dest)
    except RuntimeError:
        logger.warning('No running event loop — backup scheduler not started')
