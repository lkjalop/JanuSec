## Rule Hardening PR Template

Use this template for PRs that harden correlation rules.

- **Rule ID / File:** (e.g. `weekX/expanded_batch.py::pers_scheduled_task_lolbin_args`)
- **Author / Owner:**
- **Summary:** One-line description of the rule and intended detection.
- **Factors:** List of features used (field names + brief rationale).
- **MITRE:** ATT&CK IDs / techniques targeted.
- **Unit Vectors:** Files under `tests/data/auto_audit/` used to validate behavior.
- **Expected TP / FP Baseline:** numeric thresholds or qualitative notes.
- **HopGraph Queries / Mocking:** Describe graph expectations and provide mocked output for tests.
- **A/B Plan:** How this rule will be deployed as a variant (control/variant names).
- **Rollback / Guardrails:** Conditions to auto-roll back (precision drop, high FP delta).
- **Tests Added:** List of tests / locations and quick run commands.

Checklist:
- [ ] Spec included
- [ ] Unit tests added and passing
- [ ] Precision metrics wired to `precision_metrics` repo
- [ ] AB variant configured and documented
- [ ] PR size < 400 lines (prefer smaller incremental changes)
