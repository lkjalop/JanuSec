"""Train a baseline ml_score model on synthetic examples.
Saves model bundle to `data/models/ml_score.pkl` by default.
Run: python scripts/train_ml_score.py
"""
from __future__ import annotations
import random
import os
from src.ml.feature_extractor import extract_row_features
from src.ml.model import train_model, save_model

def synth_row(verdict: str, dread: float, factors: int, hotspots: bool, age: int, conf: float):
    return {
        'verdict': verdict,
        '_dread': {'score': dread},
        'factors': ['f{}'.format(i) for i in range(factors)],
        'graph_context': {'hotspots': [1] if hotspots else [] , 'mapping_stats': {'a':1} if hotspots else {}},
        'ts': max(0,  int( time_now := (int(__import__('time').time())) - age )),
        'llm_meta': {'confidence': conf}
    }

def make_dataset(n=500):
    X = []
    y = []
    for i in range(n):
        verdict = random.choices(['CRITICAL','HIGH','SUSPICIOUS','MEDIUM','LOW'], [0.05,0.1,0.2,0.4,0.25])[0]
        dread = random.random() * 10.0
        factors = random.randint(0,8)
        hotspots = random.random() < 0.2
        age = random.randint(0, 86400)
        conf = random.random()
        row = synth_row(verdict, dread, factors, hotspots, age, conf)
        X.append(extract_row_features(row, {'created': int(__import__('time').time())}))
        # synthetic target: composite of handcrafted formula + noise
        base = 0.0
        if verdict == 'CRITICAL': base += 40
        elif verdict == 'HIGH': base += 25
        elif verdict in {'SUSPICIOUS','FAIL'}: base += 18
        base += dread * 0.8
        base += min(20.0, factors * 2.5)
        if hotspots: base += 8.0
        if conf < 0.5: base += (0.5 - conf) * 10.0
        noise = random.gauss(0, 4.0)
        y.append(max(0.0, min(100.0, base + noise)))
    return X, y

def main():
    X,y = make_dataset(800)
    out = train_model(X,y, None)
    model_dir = os.path.join(os.getcwd(), 'data', 'models')
    os.makedirs(model_dir, exist_ok=True)
    path = os.path.join(model_dir, 'ml_score.pkl')
    save_model(out, path)
    print('Saved model to', path)

if __name__ == '__main__':
    main()
