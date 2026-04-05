import os
import json
import tempfile
import pytest
try:
    from moto import mock_s3
except Exception:
    mock_s3 = None

# Some moto builds expose a placeholder that raises ImportError when invoked.
# Probe the decorator to ensure it's usable; otherwise skip the entire module.
if mock_s3 is None:
    pytest.skip("moto.mock_s3 not importable; skipping S3 collect tests", allow_module_level=True)
else:
    try:
        # attempt to instantiate and enter/exit to ensure backend is present
        ctx = mock_s3()
        try:
            ctx.__enter__()
            ctx.__exit__(None, None, None)
        except ImportError:
            pytest.skip("moto.mock_s3 not available at runtime; skipping S3 collect tests", allow_module_level=True)
    except ImportError:
        pytest.skip("moto.mock_s3 not available at runtime; skipping S3 collect tests", allow_module_level=True)
import boto3

from src.core.forensic_store import ForensicStore

from scripts.collect_memory import sha256_file, upload_file


@mock_s3()
def test_collect_and_record(tmp_path, monkeypatch):
    # Setup moto S3
    s3 = boto3.client('s3', region_name='us-east-1')
    bucket = 'test-forensics'
    s3.create_bucket(Bucket=bucket)

    # create a small file
    f = tmp_path / 'mem.bin'
    f.write_bytes(b'hello-memory')

    checksum = sha256_file(str(f))

    # temp DB for ForensicStore
    db = tmp_path / 'forensic.db'
    os.environ['FORENSIC_DB_PATH'] = str(db)

    # call upload_file (uses moto S3)
    upload_file(str(f), bucket, 'artifacts/memory/mem.bin', kms_key_id=None, object_lock_days=None)

    # verify object exists
    obj = s3.get_object(Bucket=bucket, Key='artifacts/memory/mem.bin')
    assert obj is not None

    # simulate ForensicStore record insertion
    store = ForensicStore(str(db))
    store.insert_artifact(f's3://{bucket}/artifacts/memory/mem.bin', 'test', 1234567890, checksum, meta={'note':'test'})

    # verify DB entry
    conn = store._conn()
    cur = conn.cursor()
    cur.execute('SELECT s3_url, collector, sha256 FROM forensic_artifacts')
    row = cur.fetchone()
    assert row[0] == f's3://{bucket}/artifacts/memory/mem.bin'
    assert row[1] == 'test'
    assert row[2] == checksum
