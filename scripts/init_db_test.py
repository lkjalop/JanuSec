import asyncio
import os
import sys
from pathlib import Path

# Ensure repo root is on sys.path so local modules import correctly
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import database_adapter

async def main():
    os.environ['DB_TYPE'] = 'sqlite'
    os.environ['SQLITE_PATH'] = 'data/janusec_test.db'
    os.environ['DB_AUTO_CONNECT'] = 'true'
    await database_adapter.init_database()
    health = await database_adapter.database_health()
    print('DB Health:', health)
    # ensure provenance tables exist via adapter methods
    if getattr(database_adapter.db_manager, 'adapter', None):
        print('Adapter type:', type(database_adapter.db_manager.adapter))
    await database_adapter.shutdown_database()

if __name__ == '__main__':
    asyncio.run(main())
