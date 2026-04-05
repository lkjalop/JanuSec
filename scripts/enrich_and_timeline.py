"""Run enrichment over dump files, write timeline JSON and export HopGraph WAL lines."""
from pathlib import Path
import json
import csv
import os
from src.enrichment.pipeline import enrich_event
from src.graph.hopgraph import GLOBAL_HOPGRAPH

ROOT = Path(__file__).resolve().parent.parent
DUMP = ROOT / 'dump'
OUT = ROOT / 'sim_reports'
OUT.mkdir(exist_ok=True)


def load_csv(p: Path):
    rows = []
    with p.open('r', encoding='utf-8') as fh:
        rdr = csv.DictReader(fh)
        for r in rdr:
            rows.append(r)
    return rows


def run():
    timeline = []
    # process email, edr, network, c2
    for fname in ['email.csv','edr.csv','network.csv','c2.csv','endpoint.csv']:
        p = DUMP / fname
        if not p.exists():
            continue
        rows = load_csv(p)
        for r in rows:
            enr = enrich_event(r)
            item = {'source_file': fname, 'raw': r, 'enrichment': enr}
            timeline.append(item)

    (OUT / 'timeline.json').write_text(json.dumps(timeline, indent=2), encoding='utf-8')

    # Export WAL (raw lines)
    walpath = GLOBAL_HOPGRAPH.wal_path
    try:
        if Path(walpath).exists():
            raw = Path(walpath).read_text(encoding='utf-8')
            (OUT / 'wal_export.log').write_text(raw, encoding='utf-8')
    except Exception:
        pass

    print('Wrote timeline.json and wal_export.log to', OUT)


if __name__ == '__main__':
    run()
