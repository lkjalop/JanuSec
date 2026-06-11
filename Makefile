.PHONY: up-migrate

up-migrate:
	./scripts/up_and_migrate.sh
.PHONY: integration-test
integration-test:
	@echo "Running integration orchestration (PowerShell)"
	@powershell -ExecutionPolicy Bypass -File scripts/run_tests_integration.ps1

.PHONY: backup
backup:
	@echo "Run pre-migration backup (PowerShell)"
	@powershell -ExecutionPolicy Bypass -File scripts/pre_migration_backup.ps1

.PHONY: install-dev
install-dev:
	python -m pip install -r requirements.txt
	python -m pip install -r requirements-dev.txt || true
	python -m pip install ruff mypy

.PHONY: test
test:
	PYTHONPATH=./src python -m pytest -q

.PHONY: test-seq
test-seq:
	PYTHONPATH=./src python scripts/run_tests_sequential.py

.PHONY: test-async
test-async:
	PYTHONPATH=./src python scripts/run_tests_async_only.py

.PHONY: lint
lint:
	python -m ruff check .

.PHONY: typecheck
typecheck:
	python -m mypy src

.PHONY: ci-install ci-lint ci-typecheck ci-test
ci-install: install-dev
ci-lint: lint
ci-typecheck: typecheck
ci-test: test

.PHONY: export-dataset
export-dataset:
	python -m ml.cli.dataset_cli --limit 2000 --out-csv calibration_export.csv --out-html calibration_export.html

.PHONY: train-baseline
train-baseline:
	python -m ml.train_baseline calibration_export.csv --out models/baseline_sigmoid.json --tracker experiments.jsonl

.PHONY: seed-synthetic
seed-synthetic:
	python -m ml.cli.seed_synthetic --count 300

.PHONY: ci-model-smoke
ci-model-smoke:
	$(MAKE) seed-synthetic
	$(MAKE) export-dataset
	$(MAKE) train-baseline

.PHONY: promote-model
promote-model:
	python -m ml.cli.promote_model --src models/baseline_sigmoid.json --name sigmoid-`date +%Y%m%d-%H%M` --alias current || echo Promote failed

# ── Clustering / narration quality gates (added 2026-06) ─────────────────────
.PHONY: quality-gate
quality-gate:  ## Fast structural gate: entities + clustering + narrator + redaction units
	PYTHONPATH=./src python -m pytest tests/test_entities.py tests/test_cloudtrail_normalization.py \
		tests/test_ioc_redaction.py tests/test_intelligence_improvements.py \
		tests/test_e2e_clustering_gate.py tests/test_phase_detectors_apt.py -q -o addopts=""

.PHONY: e2e-gate
e2e-gate:  ## Full-dataset clustering regression gate vs golden baseline (needs dump/test files/)
	PYTHONPATH=./src python scripts/e2e_assess.py

.PHONY: e2e-baseline
e2e-baseline:  ## Regenerate the e2e golden baseline (after an intentional clustering change)
	PYTHONPATH=./src python scripts/e2e_assess.py --update-baseline

.PHONY: benchmark
benchmark:  ## LLM narrator quality benchmark on real fixtures (needs local Ollama)
	PYTHONPATH=./src python scripts/llm_compare.py --models qwen2.5:14b
