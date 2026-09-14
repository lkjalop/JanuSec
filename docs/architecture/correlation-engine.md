# Correlation Engine (HopGraph)

HopGraph is a conceptual graph model used to join entities across domains (endpoint, network, identity, cloud, SBOM). The public repo describes the data model and sanitized examples of joins.

Data model (sanitized):
- Nodes: host, user, file, ip, domain, process, vulnerability
- Edges: executed_on, connected_to, accessed_by, downloaded_from, exploited_via

Example (synthetic):
- user-A executed process-X on host-001
- process-X downloaded file-Y from domain-evil
- file-Y matches vulnerable_component: log4j-core:2.14.1
- HopGraph can reconstruct path: initial_access → persistence → lateral_movement

Privacy note: Example data in this repository is synthetic and sanitized.
