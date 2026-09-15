# Emerging threat evidence contracts

Date: 2026-08-19

JanusSec treats these as investigation hypotheses with required telemetry, not
as keyword-based verdict rules. The executable profiles live in
`src/core/evidence_contract/threat_coverage.py`.

## Software and AI supply chain

Required evidence includes artifact/model digests, build and training
provenance, signer and builder identity, dependency/SBOM state, registry audit,
deployment revision and runtime lineage. SLSA provenance describes where, when
and how an artifact was produced. NIST's generative-AI SSDF profile additionally
recommends tracking models, components, training libraries, frameworks and
pipelines.

References:

- https://slsa.dev/spec/v1.2/build-provenance
- https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=958391
- https://csrc.nist.gov/pubs/ai/100/2/e2025/final

## AI model and agent compromise

Keep four distinct hypotheses: adversarial input/evasion, data or model
poisoning, model extraction/privacy leakage, and agent/tool boundary escape.
“Escape” is not a model becoming sentient; it is an agent crossing a sandbox,
tenant, authorization, data or tool boundary. Investigation therefore requires
model/deployment identity, complete interaction audit, retrieval traces, tool
requests and results, authorization decisions, sandbox audit, secret access and
egress evidence.

NIST AI 100-2 supplies the lifecycle taxonomy. Current threat intelligence also
shows malware experimentally or operationally calling LLMs at runtime for code
generation, obfuscation or command generation. These are runtime/API and process
lineage problems as well as AI-security problems.

References:

- https://csrc.nist.gov/pubs/ai/100/2/e2025/final
- https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools
- https://cloud.google.com/blog/topics/threat-intelligence/ai-vulnerability-exploitation-initial-access/

## Ransomware and data extortion

Do not reduce ransomware to file-extension or entropy alerts. Reconstruct entry,
credential use, execution, spread, file impact, recovery inhibition, backup
reachability, data access and outbound disclosure. Separate encryption,
destruction, renaming, service outage and exfiltration claims. Recovery state
requires backup audit and restoration-test evidence.

Reference: https://www.cisa.gov/stopransomware/ransomware-guide

## Steganographic delivery and exfiltration

An unusual image or high entropy is not proof of stegomalware. A defensible chain
requires carrier provenance and digest, MIME/container metadata, steganalysis or
archive analysis, decoder/loader process lineage, memory or script execution and
the transfer path. Keep delivery, command-and-control and exfiltration as
different hypotheses.

References:

- https://www.sciencedirect.com/science/article/pii/S0165168425000039
- https://www.sciencedirect.com/science/article/pii/S1574119225000495

## Placement in JanusSec

```text
artifact/content provenance ─┐
identity + authorization ────┤
endpoint/process lineage ────┤
network/cloud/email audit ───┼─> case partition -> episodes -> Evidence Pack
backup/recovery evidence ────┤                         │
model/tool/sandbox audit ────┤                         └─> corrective retrieval
steganalysis results ────────┘
```

An anomaly detector may propose a case candidate. It cannot supply missing
provenance, create a causal edge, assert encryption/exfiltration, or establish a
control nonconformity.
