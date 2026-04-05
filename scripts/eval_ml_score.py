"""Simple evaluation harness for ml_score model.
Usage: python scripts/eval_ml_score.py
This script loads data from synthetic generator, trains/evaluates a model, and prints RMSE/R2.
"""
from __future__ import annotations
import os
from src.ml.feature_extractor import extract_feature_matrix
from src.ml.model import train_model, load_model, save_model
from src.ml.scaler import save_scaler
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_squared_error, r2_score

def make_synthetic(n=1000):
    import random, time
    rows = []
    ys = []
    for _ in range(n):
        verdict = random.choices(['CRITICAL','HIGH','SUSPICIOUS','MEDIUM','LOW'], [0.05,0.1,0.2,0.4,0.25])[0]
        dread = random.random() * 10.0
        factors = random.randint(0,8)
        hotspots = random.random() < 0.2
        age = random.randint(0, 86400)
        conf = random.random()
        row = {'verdict': verdict, '_dread': {'score': dread}, 'factors': ['f{}'.format(i) for i in range(factors)], 'graph_context': {'hotspots':[1] if hotspots else []}, 'ts': int(time.time()) - age, 'llm_meta': {'confidence': conf}}
        rows.append(row)
        base = 0.0
        if verdict == 'CRITICAL': base += 40
        elif verdict == 'HIGH': base += 25
        elif verdict in {'SUSPICIOUS','FAIL'}: base += 18
        base += dread * 0.8
        base += min(20.0, factors * 2.5)
        if hotspots: base += 8.0
        if conf < 0.5: base += (0.5 - conf) * 10.0
        ys.append(max(0.0, min(100.0, base + random.gauss(0,4.0))))
    return rows, ys

def main():
    rows, y = make_synthetic(800)
    Xd = extract_feature_matrix(rows)
    feature_names = list(Xd[0].keys())
    X = np.array([[x.get(f,0.0) for f in feature_names] for x in Xd])
    yv = np.array(y)
    # split
    n = len(yv)
    idx = int(n*0.8)
    Xtr, Xte = X[:idx], X[idx:]
    ytr, yte = yv[:idx], yv[idx:]
    # scale
    scaler = StandardScaler()
    Xtr_s = scaler.fit_transform(Xtr)
    Xte_s = scaler.transform(Xte)
    # train using model.train_model that expects feature dicts - adapt by converting back
    Xtr_dicts = [dict(zip(feature_names, list(row))) for row in Xtr_s.tolist()]
    model_bundle = train_model(Xtr_dicts, ytr.tolist(), None)
    # save scaler and model
    model_dir = os.path.join(os.getcwd(), 'data', 'models')
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, 'ml_score.pkl')
    save_model(model_bundle, model_path)
    save_scaler(scaler, os.path.join(model_dir, 'ml_score_scaler.pkl'))
    # predict
    Xte_dicts = [dict(zip(feature_names, list(row))) for row in Xte_s.tolist()]
    preds = model_bundle['model'].predict(Xte_s) if hasattr(model_bundle['model'], 'predict') else []
    if len(preds) != len(yte):
        preds = [float(p) for p in model_bundle['model'].predict(Xte_s)]
    rmse = mean_squared_error(yte, preds, squared=False)
    r2 = r2_score(yte, preds)
    print(f"Eval RMSE: {rmse:.3f} R2: {r2:.3f}")

if __name__ == '__main__':
    main()
