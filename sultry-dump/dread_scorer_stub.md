# DREAD Scorer Stub (Design Extraction)

Original sources reference a `score_dread` function (e.g., `src/analysis/dread_scorer.py`). For Sultry.ai implement a modular scorer:

```python
def score_dread(factors: dict[str,float]) -> dict[str,float]:
    # factors: normalized factor_id -> weight (0..1)
    # Return components scaled 0..1
    comp = {
        'damage': min(1.0, 0.2 + 0.6*len([f for f in factors if 'persistence' in f])/5),
        'reproducibility': 0.5,
        'exploitability': min(1.0, 0.3 + 0.7*len([f for f in factors if 'lolbin' in f])/3),
        'affected_users': 0.4,
        'discoverability': 0.5
    }
    return comp
```

Aggregate:
```
score = sum(comp.values()) / len(comp)
severity = 'high' if score >= 0.66 else 'medium' if score >= 0.33 else 'low'
```

Enhancements:
- Weight factors via impact taxonomy mapping file.
- Provide calibration set & telemetry drift detection.
- Allow alternative models (e.g., logistic regression) behind same interface.
