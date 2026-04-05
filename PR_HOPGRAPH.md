PR: HopGraph persistence, BGP wiring tests, eBPF smoke harness, and demo tools

Summary:
- Replace identity snapshot JSON format with SQLite-backed persistence (atomic), include ewma and high_value metadata.
- Wire BGP client prefixes into the NetworkHopGraph (route nodes).
- Add unit tests for BGP wiring, metadata edges, eBPF smoke harness, and identity snapshot round-trip.
- Add demo_tools CLI and a small demo notebook to exercise snapshot and eBPF stage.
- Update `.vscode/tasks.json` to include the new tests in the `pytest-new` task.

Files of interest:
- src/core/graph/identity_hopgraph.py (persistence changes)
- src/integrations/bgp_client.py (push prefixes into network graph)
- src/core/graph/network_hopgraph.py (ingest_bgp_prefix)
- tests/test_bgp_network_wiring.py
- tests/test_bgp_metadata_edges.py
- tests/test_ebpf_smoke.py
- tests/test_identity_snapshot.py
- scripts/demo_tools.py
- docs/DEMO_TOOLS_README.md
- notebooks/demo_snapshot_and_ebpf.ipynb

Notes:
- I did not push the branch; please run `git push` with your credentials if you want these changes in the remote repository.
- I updated the vscode task to run the new tests locally.
