import asyncio
import os
from database_adapter import db_manager, store_dedup_run, store_dedup_cluster, get_dedup_runs, get_dedup_clusters

async def main():
    os.environ['DB_TYPE'] = 'sqlite'
    os.environ['SQLITE_PATH'] = 'data/test_dedup.db'
    await db_manager.initialize()
    run_id = 'test-run-1'
    await store_dedup_run(run_id, {'k':2}, {'total_rows':3, 'clusters':2}, tenant_id='default')
    await store_dedup_cluster(run_id, 1, {'user':'alice'}, [{'user':'alice','host':'h1'}], {'size':1})
    runs = await get_dedup_runs()
    print('runs', runs)
    clusters = await get_dedup_clusters(run_id)
    print('clusters', clusters)
    await db_manager.shutdown()

asyncio.run(main())
