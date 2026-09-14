CREATE TABLE IF NOT EXISTS precision_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    day TEXT NOT NULL,
    tenant_id TEXT,
    tp INTEGER,
    fp INTEGER,
    fn INTEGER,
    tn INTEGER,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS ab_test_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id TEXT,
    tenant_id TEXT,
    variant TEXT,
    tp INTEGER,
    fp INTEGER,
    fn INTEGER,
    started_at TEXT,
    ended_at TEXT,
    created_at TEXT
);
