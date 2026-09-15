from __future__ import annotations

import argparse
import time
from core.factor_attribution_store import FactorAttributionSnapshot, FACTOR_ATTRIBUTIONS
from core.labels_store import LABELS


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Seed synthetic labeled snapshots for calibration")
    p.add_argument("--count", type=int, default=200)
    args = p.parse_args(argv)
    now = time.time()
    for i in range(args.count):
        eid = f"syn-{i}"
        rs = 0.2 + 0.6 * ((i % 10) / 10.0)
        lab = 'tp' if i % 2 == 0 else 'fp'
        snap = FactorAttributionSnapshot(
            event_id=eid,
            ts=now + i,
            factors=['syn:f1','syn:f2'] if i % 3 == 0 else ['syn:f3'],
            breakdown=[{'factor':'syn:f1','contribution':rs}],
            score=rs,
            raw_score=rs,
            confidence=0.9,
            variance=0.0,
            ci95=(max(0.0, rs-0.1), min(1.0, rs+0.1)),
        )
        FACTOR_ATTRIBUTIONS.add_snapshot(snap)
        LABELS.add_label(eid, lab, 'synthetic')
    print(f"Seeded {args.count} synthetic samples")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
