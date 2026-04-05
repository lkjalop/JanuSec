# Pseudocode phases
1. pip install -r requirements.txt
2. ruff check .
3. mypy (selective modules)
4. bandit -q -r src/
5. python scripts/replay_harness.py --input sample_events.jsonl --output run1.jsonl
6. python scripts/replay_harness.py --input sample_events.jsonl --output run2.jsonl
7. diff run1.jsonl run2.jsonl > replay_diff.txt
8. curl http://localhost:8000/metrics > metrics_snapshot.txt
9. custom import diff script (compare to requirements)
10. aggregate -> audit_results.json