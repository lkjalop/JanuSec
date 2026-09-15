# CRQ Calibration & Shadow-Run Plan

Goal: collect high-quality ground-truth labels for persisted CRQ observations to calibrate TF‑IDF classifier and factor priors.

1) Duration: 4–8 weeks continuous shadow run.
2) Scope: route persisted observations from enrichment consumer to a 'shadow' store and tag with `shadow_run:true`.
3) Label collection:
   - Analysts review recent CRQ items via UI; provide labels: TP/FP/undetermined.
   - Provide an API `/api/v1/crq/label` for quick labeling (incident id, label, annotator).
4) Storage: store labels in `data/crq_labels.json` with schema `{obs_id, label, annotator, ts, notes}`.
5) Metrics & cadence:
   - Weekly reports: precision, recall, confusion matrix, high-FP patterns.
   - After 4 weeks, compute calibration parameters and update classifier or thresholds.
6) Feedback loop:
   - Use labeled data to retrain TF‑IDF and recompute feature weights.
   - Deploy updated model to staging for validation before production rollout.

*** End Patch