Join Helpers for Rule Authors
================================

Purpose:

Functions:

Usage (from a rule module):

1. Import the helper:

   from src.core.rules.join_helpers import join_identities

2. Call with either a HopGraph instance or a callable adjacency accessor:

   # Using the app's hopgraph instance
   hg = request.app.state.hopgraph
   users = join_identities(hg, 'host:myhost.example.com')

   # Using a lightweight callable (useful in unit tests)
   def adj(n):
       return [('user:alice', 'auth', {}), ('ip:1.2.3.4', 'resolved_to', {})]
   users = join_identities(adj, 'host:myhost')

Notes:

Testing:

# Rules Join Helpers

This folder contains helpers and schema scaffolding for authoring correlation rules.

Quick usage:

- Rule schema is defined in `src/core/rules/schema.py` (Pydantic `RuleModel`).
- Use `load_rule_from_yaml(path)` to load a YAML rule into a validated model.
- Export JSON Schema with `export_json_schema(path)`.

Example rule YAML (save as `rules/examples/corr_office_macro_ps.yaml`):

```yaml
id: corr_office_macro_ps
title: Office Macro -> PowerShell spawn
description: Detect when an Office macro spawns PowerShell and then makes network connections.
enabled: true
version: '0.1'
tags: ['office','macro','powershell','execution']
conditions:
   - field: event.source
      op: eq
      value: office_macro
joins:
   - name: office_to_proc
      join_type: inner
      mapping:
         user: user
         host: host
         process: process
      max_hops: 2
actions:
   - id: create_incident
      title: Create Incident
      severity: high
      mitre: ['T1059.001','T1059']
      description: 'Macro spawned PowerShell; escalate to analyst review.'
```

Loader snippet (Python):

```python
from src.core.rules.schema import load_rule_from_yaml

rule = load_rule_from_yaml('rules/examples/corr_office_macro_ps.yaml')
print('Loaded rule:', rule.id, rule.title)
```

Design notes:

- The `joins` section is intentionally flexible: it maps canonical fields (like `user`, `host`, `process`) to graph node prefixes and provides `max_hops` for bounded traversal.
- Rule evaluation engines should use `src/core/rules/join_helpers._get_adj_list` to retrieve adjacency accessors for a graph instance, then perform read-only traversals (do not mutate the graph).
- JSON Schema export is available for CI validation and editor tooling via `export_json_schema()`.
