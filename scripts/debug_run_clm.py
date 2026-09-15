import os
import asyncio
import sqlite3
import time
from src.ml.closed_loop_manager import ClosedLoopManager

print('START debug runner')
os.environ['USE_PLATFORM_DB'] = '0'

from pathlib import Path
p = Path('data/test_clm.db')
if p.exists():
    try:
        p.unlink()
    except Exception:
        pass

clm = ClosedLoopManager(db_path=str(p))
print('ClosedLoopManager created')

print('Adding feedback')
clm.add_feedback('evt-1', ['factor_a','factor_b'], 1)

print('ready_to_learn ->', clm.ready_to_learn())

print('about to propose weights (sync)')
try:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    res = loop.run_until_complete(clm.propose_weights())
    print('propose_weights returned:', res)
    loop.close()
except Exception as e:
    print('propose_weights exception:', type(e), e)

print('list_candidates ->', clm.list_candidates())
print('approve_candidate ->')
try:
    applied = clm.approve_candidate(1, actor='tester')
    print('applied:', applied)
except Exception as e:
    print('approve_candidate exception:', type(e), e)

print('DB audit count')
try:
    conn = sqlite3.connect(str(p))
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM factor_weight_audit")
    cnt = cur.fetchone()[0]
    conn.close()
    print('audit count:', cnt)
except Exception as e:
    print('db error', e)

print('DONE')
