Demo tools
----------

The repository includes a small demo CLI `scripts/demo_tools.py` to show snapshot save/load and a sample eBPF ingestion. Usage examples:

Save a snapshot (SQLite DB):

```powershell
python -m scripts.demo_tools save-snapshot .\demo_snapshot.db
```

Load a snapshot:

```powershell
python -m scripts.demo_tools load-snapshot .\demo_snapshot.db
```

Show eBPF stage output for a sample Falco event:

```powershell
python -m scripts.demo_tools show-ebpf
```

The demo script is intentionally lightweight and uses the same StageContext shape as the pipeline. It helps during local demos and smoke tests.
