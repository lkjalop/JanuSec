"""Private-state verification helper; outputs only counts and boolean proofs."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.pilot_state import configure
from src.backup.pilot_state import state_lock

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--state', type=Path, required=True)
parser.add_argument('--assessment', required=True)
parser.add_argument('--canary-sha256', required=True)
parser.add_argument('--expected-rows', type=int)
args = parser.parse_args()
state = args.state.resolve()
with state_lock(state):
    configure(state)
    from src.integrations.tenant_store import FileSecretBackend
    from src.integrations.checkpoint_store import CheckpointStore
    from src.core.connectors.checkpoint_store_v2 import CheckpointStoreV2
    from src.core.ingest import store
    value = FileSecretBackend().load('pilot-customer/recovery-canary')['value']
    assert hashlib.sha256(value.encode()).hexdigest() == args.canary_sha256
    assert CheckpointStore().load('recovery-canary') == 'cursor-42'
    assert CheckpointStoreV2().load('recovery-canary', 'stream')['cursor'] == 'cursor-43'
    files = store.raw_files_for(args.assessment)
    assert len(files) == 4 and all(Path(path).is_relative_to(state) for path, _ in files)
    # The actual append-only ledger and history database must also be present.
    import sqlite3
    with sqlite3.connect(state / 'data/platform.sqlite') as db:
        ledger_rows = db.execute('SELECT count(*) FROM evidence_ledger').fetchone()[0]
    assert ledger_rows > 0
    counts = store._db().execute('SELECT count(*), count(DISTINCT row_index) FROM normalized_rows WHERE assessment_id=?',
                                 [args.assessment]).fetchone()
    if args.expected_rows is not None:
        assert counts == (args.expected_rows, args.expected_rows), 'physical_duplicate_or_missing_rows'
        assert store.get_job(args.assessment)['status'] == 'ready'
    store._conn.close()
print(json.dumps({'encrypted_secret_recovered': True, 'checkpoint_formats_recovered': 2,
                  'raw_captures_in_restored_root': len(files), 'ledger_records': ledger_rows,
                  'physical_rows': counts[0], 'distinct_row_indices': counts[1]}))
