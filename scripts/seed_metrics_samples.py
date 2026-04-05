import os
from datetime import date, timedelta
from src.repositories.precision_metrics_repo import PrecisionMetricsRepo

DB_PATH = os.getenv('JANUSEC_SQLITE_PATH', 'data/janusec.db')
TENANT = os.getenv('SAMPLE_TENANT', 'default')

if __name__ == '__main__':
    repo = PrecisionMetricsRepo(DB_PATH)
    today = date.today()
    # Seed 28 days of synthetic metrics
    for i in range(28):
        d = today - timedelta(days=(27 - i))
        # simple trend: gradually improving precision/recall
        tp = 80 + i
        fp = max(5, 30 - i)
        fn = max(3, 20 - (i//2))
        repo.insert_daily_metrics(d, TENANT, tp=tp, fp=fp, fn=fn)
    print('Seeded daily precision metrics for tenant', TENANT)
