#!/usr/bin/env python3
"""Offline helper to train the IsolationForest from recent in-memory graph state.

Usage: python scripts/train_isolation.py --out data/iso_model.pkl --lookback 1000
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path

# attempt to import application globals
try:
    from src.core.graph.identity_hopgraph import GLOBAL_IDENTITY_GRAPH as G
    from src.ml.isolation_model import GLOBAL_ISO_MODEL
except Exception:
    G = None
    GLOBAL_ISO_MODEL = None


def build_vectors(lookback: int = 1000, tenant: str | None = None):
    X = []
    if not G:
        return X
    items = list(G._recent_edges.items())
    items.sort(key=lambda it: len(it[1]) if it and it[1] else 0, reverse=True)
    for ident, dq in items:
        if tenant and isinstance(ident, str) and not ident.startswith(f"{tenant}:"):
            continue
        cnt = len(dq)
        hosts = len(set(e.get('dst_host') for e in dq if e.get('dst_host')))
        X.append([float(cnt), float(hosts)])
        if len(X) >= lookback:
            break
    return X


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--out', '-o', default=os.getenv('ISO_MODEL_PATH', 'data/iso_model.pkl'))
    p.add_argument('--lookback', '-n', type=int, default=1000)
    p.add_argument('--tenant', '-t', default=None)
    p.add_argument('--export-only', action='store_true', help='Export per-tenant datasets and exit')
    p.add_argument('--export-dir', default=os.getenv('ISO_EXPORT_DIR', 'data/iso_export'))
    p.add_argument('--per-tenant-train', action='store_true', help='Train a model per tenant and save under data/iso_models/')
    p.add_argument('--min-samples', type=int, default=20, help='Minimum vectors required to train a per-tenant model')
    p.add_argument('--sample-cap', type=int, default=2000, help='Maximum vectors to use per tenant (sample if more)')
    p.add_argument('--val-ratio', type=float, default=0.2, help='Validation ratio for per-tenant training')
    args = p.parse_args()

    print('Building vectors...')
    X = build_vectors(args.lookback, args.tenant)
    print(f'Collected {len(X)} vectors')

    # If export-only, write per-tenant datasets and exit (create export dir even if X empty)
    if args.export_only:
        Path(args.export_dir).mkdir(parents=True, exist_ok=True)
        import json
        out_path = Path(args.export_dir) / (f"{args.tenant or 'all'}_vectors.json")
        with out_path.open('w', encoding='utf-8') as f:
            json.dump(X, f)
        print('Exported vectors to', str(out_path))
        return

    if not X:
        print('No data available in GLOBAL_IDENTITY_GRAPH._recent_edges')
        return

    if args.per_tenant_train:
        # Build per-tenant buckets from G._recent_edges
        if not G:
            print('GLOBAL_IDENTITY_GRAPH not available')
            return
        buckets = {}
        for ident, dq in list(G._recent_edges.items()):
            tenant_id = None
            if isinstance(ident, str) and ':' in ident:
                tenant_id = ident.split(':', 1)[0]
            tenant_id = tenant_id or 'default'
            cnt = len(dq)
            hosts = len(set(e.get('dst_host') for e in dq if e.get('dst_host')))
            buckets.setdefault(tenant_id, []).append([float(cnt), float(hosts)])
        models_dir = Path(os.getenv('ISO_MODELS_DIR', 'data/iso_models'))
        models_dir.mkdir(parents=True, exist_ok=True)
        if not GLOBAL_ISO_MODEL:
            print('GLOBAL_ISO_MODEL not importable; ensure sklearn available to train')
            return
        # Train a fresh IsolationWrapper per tenant by instantiating IsolationWrapper and fitting
        from src.ml.isolation_model import IsolationWrapper
        import random
        for t, vecs in buckets.items():
            if not vecs or len(vecs) < args.min_samples:
                print(f'skipping tenant {t}: insufficient samples ({len(vecs)})')
                continue
            # sample up to sample_cap
            if len(vecs) > args.sample_cap:
                random.shuffle(vecs)
                vecs = vecs[: args.sample_cap]
            # split train/validation
            split = max(1, int(len(vecs) * (1.0 - args.val_ratio)))
            train_vecs = vecs[:split]
            val_vecs = vecs[split:]
            model_path = models_dir / f"{t}.pkl"
            print(f'Training tenant {t} with {len(train_vecs)} train / {len(val_vecs)} val vectors -> {model_path}')
            try:
                w = IsolationWrapper(model_path=str(model_path))
                if not w.enabled:
                    print('skipping tenant', t, '(iso wrapper disabled)')
                    continue
                w.fit_partial(train_vecs, persist=True, path=str(model_path))
                # optionally compute validation anomaly scores (best-effort)
                try:
                    scores = [w.score(x) for x in val_vecs]
                    avg_score = sum(scores) / len(scores) if scores else 0.0
                    print(f'validation avg anomaly score: {avg_score:.4f}')
                except Exception:
                    pass
            except Exception as e:
                print('error training tenant', t, e)
        print('Per-tenant training complete')
        return

    if not GLOBAL_ISO_MODEL:
        print('GLOBAL_ISO_MODEL not importable; ensure application context is available')
        return
    print('Training model...')
    GLOBAL_ISO_MODEL.fit_partial(X, persist=True, path=args.out)
    print('Done. Model persisted to', args.out)


if __name__ == '__main__':
    main()
