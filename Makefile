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
