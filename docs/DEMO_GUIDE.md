# Customer proof-of-concept demonstration

JanuSec's current demonstration is an incident-evidence review workflow. Start
with a customer question: can an analyst distinguish separate incidents, explain
the supporting telemetry, and preserve the same evidence in the handoff report?

## Prepare

Use the loopback preview described in the README. It uses a public development
key and deterministic execution. It is not a customer deployment configuration.

Run the corpus browser checks against that preview:

```powershell
python -m pip install "playwright>=1.50,<2"
python -m playwright install chromium
python scripts/verify_pilot_corpora.py --base-url http://127.0.0.1:8081 --output tmp_preview/corpus-browser
```

The script verifies the twelve input hashes, uploads the three complete corpora,
checks stored row counts against independent parser counts, grades explicit case
assertions, and clicks evidence, graph, timeline, retrieval and action tabs. It
also checks case switching, evidence drilldown, historical export receipts,
reload and mobile layout. Screenshots and JSON results stay in the output folder.

Use an isolated instance and run the demonstration checks serially. These are
functional acceptance checks, not a concurrent-load certification. See the
[measured corpus results](verification/2026-09-14-corpus-pilot/README.md).

## Ten-minute walkthrough

| Time | Show | Customer question answered |
|---|---|---|
| 0–1 min | Source inventory, formats, capture hashes and scope | Which systems and investigation window are represented? |
| 1–3 min | Meridian's three separate investigations | Have unrelated actors been mixed into one incident? |
| 3–5 min | Select a milestone, inspect its records, then open the timeline | Which observations support this claim? |
| 5–6 min | Vesper's cumulative transfer evidence and actor/target distinction | Can individually small events form a supported longer sequence? |
| 6–7 min | Select a recorded knowledge time and export the GRC pack | Does the handoff contain the same case and evidence? |
| 7–8 min | Upload a deliberately malformed synthetic file | Does missing input produce an explicit failure? |
| 8–9 min | Compile an Evidence Pack and run the deterministic reasoner | Are the run and its limitations recorded? |
| 9–10 min | Explain missing business mapping, control evidence and next review | What can the customer conclude, and what information is still needed? |

Keep the large assessments prepared before a meeting; retain the original upload
receipts and automated full-upload results. A prepared case is not a live
connector demonstration. Show a fresh small upload and an explicit failure live.

The public corpora are synthetic regression data. Meridian has three labeled
positive assertions; Vesper has one. Santos currently has a suppression assertion
and no positive recall labels. These checks do not measure general attack recall.

## State the boundaries plainly

- A source event, a derived relationship and a reviewer conclusion are distinct.
- A model completion receipt does not mean the model's answer passed quality review.
- A candidate technique/control mapping does not establish a failed control.
- Empty action plans mean no qualified action was projected. Do not demonstrate
  them as a completed corrective-action workflow.
- Historical views only reconstruct states that were captured. Older inputs may
  need re-ingestion to acquire the latest evidence-reference fixes.
- Customer source collection, authentication, recovery, retention and correction
  verification require a separately agreed pilot.

## Agree success criteria before collecting customer data

Record the data owner, approved sources, expected volume, required fields,
timestamp semantics, intended destinations, retention and acceptable loss policy.
Agree the positive and benign examples and who labels them. Measure ingestion
counts, rejected inputs, processing latency, resource use and analyst steps.

For a telemetry-routing proof of concept, retain a raw copy and compare security
results before and after transformation. Report measured event/byte changes and
test destination failure and replay. Cost savings require the customer's actual
pricing and retention assumptions; do not turn a byte ratio into an invented ROI.

## Pilot exit evidence

A customer pilot needs an approved source collection receipt, a tenant-owned case,
restart/checkpoint recovery, a reviewed proposed correction, a provider action
receipt and a later observation showing the result. Also demonstrate restoring
the evidence databases, projections, history, checkpoints and required keys in a
separate environment. A process restart alone is not a backup-restore test.
