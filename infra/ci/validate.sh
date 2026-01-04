#!/usr/bin/env bash
set -euo pipefail
echo "Running terraform init (no backend)"
cd "$(dirname "$0")"/.. || exit 1
terraform -version || true
cd terraform
terraform init -backend=false
echo "Running python unit tests (ebpf correlation)"
cd ../../
python -m pytest -q tests/test_ebpf_correlation.py tests/test_falco_adapter.py
echo "CI validation complete"
