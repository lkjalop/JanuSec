# Option C Manual Testing Checklist

Use this runbook after deploying the updated CSV Analyzer + Deep Analysis experience.

## CSV Analyzer

- [ ] Start platform: `python run_platform.py`
- [ ] Open http://localhost:8000/static/csv_analyzer.html
- [ ] Upload `tests/test_data/option_c_demo.csv`
- [ ] Confirm domain badges render (NETWORK/ENDPOINT/GENERIC with confidence)
- [ ] Confirm `powershell.exe` shows ENDPOINT; `svchost.exe` shows NETWORK

## Investigate Further

- [ ] Click “Investigate Further” on the `powershell.exe` row
- [ ] Verify `csv_deep_analysis.html` opens with populated summary
- [ ] Confirm LLM summary, MITRE mapping, and pipeline stages render

## HopGraph

- [ ] Scroll to “Attack Graph Reconstruction”
- [ ] Ensure the graph canvas loads nodes/edges
- [ ] Toggle timeline + correlation explanation — verify content

## AI Insights

- [ ] Click “Generate Detailed DREAD Scenarios”; confirm text + running cost update (~$0.001)
- [ ] Click “Generate Collection Playbook”; ensure deterministic steps show, cost stays $0
- [ ] Click “Generate Lateral Movement Hunt Query”; verify KQL/SPL/Sigma snippets + cost (~$0.0008)
- [ ] Click “Generate Executive Summary”; confirm two-paragraph summary + cost (~$0.0005)

## Historical Context

- [ ] Back in CSV Analyzer, open another `powershell.exe` row via “Investigate Further”
- [ ] Confirm Tier 2 prompt references “14 days ago” confirmed-malicious incident
- [ ] Validate analyst notes section saves to localStorage (optional)

Record findings or screenshots and attach to the demo readiness notes if any step fails.
