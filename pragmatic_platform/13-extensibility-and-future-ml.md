# Extensibility & Future ML Roadmap

## Philosophy
Add ML only where deterministic + heuristic approaches plateau in precision/coverage trade-off or operational cost.

## Near-Term (Post-MVP) Enhancements
| Capability | Approach | Trigger to Implement |
|------------|----------|----------------------|
| Similarity Clustering | MinHash / feature hashing over factors | Duplicate investigations > threshold |
| Outlier Scoring | Robust z-score / isolation forest (lightweight) | Missed anomalies post calibration |
| Temporal Pattern Embedding | Sliding window vectorization + simple autoencoder | APT false negatives observed |
| Policy Optimization | Multi-armed bandit for threshold tuning | Manual tuning fatigue |

## Mid-Term (Strategic)
| Capability | Approach | Value |
|-----------|---------|-------|
| Neuromorphic-Lite | Event spike encoding + reservoir / echo state network scoring | Differentiated marketing + sequence sensitivity |
| Graph Embeddings | Node2Vec/LightGCN for infra relationship risk scoring | Campaign clustering accuracy |
| Language Assistance | Small local model for intent expansion | Analyst productivity |
| Adaptive Playbook Ranking | Reinforcement signal from action success | Response optimization |

## Long-Term (Optional)
| Capability | Approach |
|-----------|---------|
| Full Sequence Modeling | Transformer w/ streaming window | Rich multi-entity temporal correlation |
| Generative Simulation | Synthetic rare scenario generation | Stress testing & calibration |

## Embedding Strategy (Incremental)
1. Start with deterministic hash signature: sorted factors → SHA256 → bucket for similarity.
2. Extend to sparse binary vector (factor presence) → MinHash signatures.
3. Introduce learned dimension reduction only if grouping precision insufficient.

## Data Contracts for ML
```
TrainingRecord {
  ts,
  event_id,
  factors: [string],
  disposition_final,
  confidence,
  cluster_id?,
  playbook_outcome?,
  feedback_label? (analyst)
}
```

## Model Governance Hooks
- Version each model; include `model_versions` map in decisions when used.
- Maintain calibration stats per model version.
- Add factor `model_out_of_distribution` when drift detector triggers.

## Safety & Explainability
- Each ML component MUST supply a feature contribution list if it influences confidence ≥ +0.05.
- Fallback path: if model latency > budget, skip without blocking pipeline.

## Retirement / Pruning
- Remove ML component if marginal precision gain < 1% over 4 weeks AND maintenance overhead > threshold.

## Open Questions
1. Do we treat neuromorphic-lite and temporal embedding as separate pluggable modules? (Yes, independent toggles.)
2. Introduce unified feature store early or defer? (Defer until >3 ML components.)
