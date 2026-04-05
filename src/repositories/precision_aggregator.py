import time
import aiosqlite
from typing import Optional
import json

DB_PATH = 'data/app.db'


class PrecisionAggregator:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DB_PATH

    async def init_db(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('''
            CREATE TABLE IF NOT EXISTS precision_daily (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                day INTEGER NOT NULL,
                rule_id TEXT NOT NULL,
                ab_variant TEXT,
                tp INTEGER DEFAULT 0,
                fp INTEGER DEFAULT 0,
                UNIQUE(day, rule_id, ab_variant)
            )
            ''')
            await db.commit()

    async def aggregate_day(self, day_ts: int, precision_repo_path: str = 'data/precision_metrics.jsonl'):
        day = int(day_ts)
        counts = {}
        try:
            with open(precision_repo_path, 'r', encoding='utf-8') as fh:
                for line in fh:
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    ts = int(obj.get('ts', 0))
                    if ts < day or ts >= day + 86400:
                        continue
                    rule = obj.get('rule_id') or 'unknown'
                    variant = obj.get('ab_variant') or 'control'
                    key = (rule, variant)
                    if key not in counts:
                        counts[key] = {'tp': 0, 'fp': 0}
                    if obj.get('label') == 'TP':
                        counts[key]['tp'] += 1
                    else:
                        counts[key]['fp'] += 1
        except FileNotFoundError:
            return

        async with aiosqlite.connect(self.db_path) as db:
            for (rule, variant), vals in counts.items():
                await db.execute('''
                INSERT INTO precision_daily(day,rule_id,ab_variant,tp,fp)
                VALUES(?,?,?,?,?)
                ON CONFLICT(day,rule_id,ab_variant) DO UPDATE SET tp=tp+excluded.tp, fp=fp+excluded.fp
                ''', (day, rule, variant, vals['tp'], vals['fp']))
            await db.commit()
