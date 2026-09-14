"""Simulate webhook EWMA behavior under different noise/attack models and output TP/FP/FN summary CSV.

Usage: python scripts/ewma_roc.py
"""
import csv
import random
import math
import time
from statistics import mean

def simulate(alpha, threshold, cooldown, seq):
    # seq: list of 0/1 error signals
    s = 0.0
    last_alert = -999999
    tp = fp = fn = tn = 0
    for i, val in enumerate(seq):
        s = (1 - alpha) * s + alpha * val
        now = i
        alerted = False
        if s >= threshold and (now - last_alert) >= cooldown:
            alerted = True
            last_alert = now
        # For this synthetic test: label true if current window contains an attack (val==1)
        is_attack = val == 1
        if alerted and is_attack:
            tp += 1
        elif alerted and not is_attack:
            fp += 1
        elif not alerted and is_attack:
            fn += 1
        else:
            tn += 1
    return {'alpha': alpha, 'threshold': threshold, 'cooldown': cooldown, 'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn}

def generate_sequence(length=1000, attack_prob=0.01, burst_prob=0.2):
    seq = []
    i = 0
    while i < length:
        if random.random() < attack_prob:
            # generate a burst
            blen = max(1, int(random.expovariate(1.0/burst_prob)))
            for _ in range(blen):
                if i >= length: break
                seq.append(1)
                i += 1
        else:
            seq.append(0)
            i += 1
    return seq

def main():
    out = 'ewma_roc_summary.csv'
    seq = generate_sequence(5000, attack_prob=0.005, burst_prob=5)
    alphas = [0.1, 0.3, 0.6]
    thresholds = [0.2, 0.4, 0.6]
    cooldowns = [1, 5, 20]
    rows = []
    for a in alphas:
        for t in thresholds:
            for c in cooldowns:
                res = simulate(a, t, c, seq)
                rows.append(res)
    with open(out, 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=['alpha','threshold','cooldown','tp','fp','fn','tn'])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print('Wrote', out)

if __name__ == '__main__':
    main()
