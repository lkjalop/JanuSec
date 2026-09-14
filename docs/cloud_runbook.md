# Cloud instrumented benchmark runbook

This runbook describes how to run the instrumented ingestion and extraction benchmarks in a cloud VM and map CPU-seconds to $/event. It provides example instance choices for AWS/GCP/Azure and minimal Terraform snippets to provision a single VM.

Goal
- Measure CPU-seconds and wall time for ingestion + explain_chain extraction for a representative dataset (for example `data/benchmarking/benchmarks/benchmark_campaign_v2_10000`).
- Convert CPU-seconds to $ using on-demand pricing for a chosen instance type.

Overview
1. Provision a VM with Python 3.11, git, and required deps (project venv).
2. Upload the dataset (or use `scripts/generate_synthetic_benchmarks_v3.py` to create one on the instance).
3. Run the instrumented ingestion script `python -m scripts.instrumented_cost_run --dataset <path> --out <out.json>` to capture wall/cpu/memory and event counts.
4. Run extraction at chosen operating point (e.g., top_k=10, max_depth=8, beam_width=8) and measure extraction times (the evaluator captures explain runs). Capture total CPU-seconds.
5. Map CPU-seconds to $ using provider on-demand CPU-hour price. Example: AWS c6i.large 1 vCPU = $0.0464/hr (adjust for region/current price). Convert: $/event = (cpu_seconds / 3600) * price_per_vcpu_hour / events_processed.

Provider snippets

AWS (example, small):
- instance: c6i.large (2 vCPU) or t3.large for burstable testing.

Terraform example (minimal):
```hcl
provider "aws" {
  region = "us-east-1"
}

resource "aws_instance" "bench" {
  ami           = "ami-0c02fb55956c7d316" # Amazon Linux 2 (example)
  instance_type = "c6i.large"
  tags = { Name = "bench-vm" }
}
```

GCP (example):
- instance: n2-standard-4 (4 vCPU) or e2-standard.

Azure (example):
- instance: Standard_D2s_v3 (2 vCPU).

Measurement details and steps
1. SSH to the instance and clone the repo, create venv and install requirements (use project's requirements or pip install -r requirements.txt). Example commands:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. Upload dataset to `/tmp/dataset` or generate with `scripts/generate_synthetic_benchmarks_v3.py`.

3. Run instrumented ingestion (example):

```powershell
python -m scripts.instrumented_cost_run --dataset /tmp/dataset --out /tmp/bench_instrument_v2_10000.json
```

The instrumented output contains: wall_seconds, cpu_seconds, mem_before, mem_after, events_count.

4. Run extraction evaluation for the operating point and capture the evaluator output (which includes explain timings if enabled):

```powershell
python -m scripts.benchmark_evaluate_ground_truth --dataset /tmp/dataset --out /tmp/bench_eval.json --beam-width 8 --top-k 10 --max-depth 8 --time-window 60
```

Cost mapping example
- Suppose instrumented ingestion cpu_seconds = 150 s, events = 10000.
- Provider vCPU on-demand price = $0.0464 / vCPU-hour. If instance has 2 vCPUs, effective CPU-hour price per machine = 2 * 0.0464 = $0.0928/hr.
- CPU-hours = cpu_seconds / 3600 = 150 / 3600 = 0.0416667 hr.
- Cost = CPU-hours * price_per_machine_hour = 0.0416667 * 0.0928 ≈ $0.003867.
- $/event = Cost / events = 0.003867 / 10000 ≈ $0.0000003867 per event.

Notes and caveats
- For defensible public claims: run multiple repeats (n≥3) and report mean ± 95% CI for wall/cpu seconds and $/event.
- Use representative instance families for production (compute-optimized for CPU-bound workloads). Avoid very small burstable types for noisy results.
- When reporting, include the dataset id, events count, instance type, region, repetition count, and exact git commit used.

If you want, I can generate Terraform snippets for all three providers with a small module and documented commands to run the benchmark and collect artifacts. Say which provider you prefer to start with.
