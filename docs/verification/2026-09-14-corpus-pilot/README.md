# Full-corpus evidence and browser verification

Date: 14 September 2026. Execution: local loopback backend, Python 3.11,
deterministic mode, Chromium. No customer provider credentials or external model
were used. The twelve original input files matched the published SHA256 manifest.

| Corpus | Stored records | Explicit case assertions | Selected-case evidence | Milestones |
|---|---:|---:|---:|---:|
| Meridian | 24,438 | 19 passed | 54 / 54 | 3 |
| Santos | 43,834 | 1 passed | 66 / 66 | 5 |
| Vesper | 98,750 | 11 passed | 445 / 445 | 7 |

All **167,022 records** were accounted for against independent parser counts.
Assertions include four labeled positive cases, twenty suppressions, six role
checks and one separation check. Santos has no positive labels, so no Santos
recall claim is made. Unlabeled cases are outside those accuracy assertions.

`scripts/verify_pilot_corpora.py` performs real browser uploads and checks the
stored case partitions. It clicks five tabs, changes cases, inspects evidence,
selects a historical cutoff, exports the matching receipt, reloads that selection
and checks mobile overflow. No corpus API responses are mocked. Results and
screenshots are written to the requested local output directory.

The final Vesper case includes the cumulative-exfiltration milestone and its 34
contributing transfer records. Before the repairs, those records could be absent
from the case boundary or receive different IDs after entity enrichment. A unit
test that only checked the detected phase did not catch that wiring failure.

The selected case views and exports were reopened after a server restart with
the same stored evidence. This proves completed-assessment persistence; it does
not prove in-flight crash recovery, a backup restore, or live provider delivery.

The serial negative/browser journey also verifies a BOM-prefixed benign record,
historical receipt/export agreement, nine linked pages and a malformed upload
that fails visibly. One earlier launch timed out while waiting for network idle
during overlapping work. The serial acceptance pass does not certify concurrent
load or a production latency objective.

## Repairs

- Preserve the assessment evidence namespace in selected-case milestones.
- Select the supporting clusters before grouping phases and generating actions.
- Compute truncation from the selected case's evidence counts.
- Retain contributing cumulative-transfer rows before freezing case boundaries.
- Assign source evidence IDs at ingestion, preserving them during enrichment and
  preventing imported IDs from choosing another assessment's references.
- Reject malformed complete-file syntax before the lenient parser can discard
  records; propagate parser failures and show a persistent failed-job message.
- Read current partition schema versions and wait for rendered browser state.

Older affected assessments should be re-ingested. Historical receipts remain
records of what was actually captured, including limitations of older versions.

## Limits and next gate

The chosen cases have zero projected action-plan items and zero qualified control
impacts. The reviewed corrective-action loop remains a pilot task. Business
mapping, regulatory applicability and containment verification remain explicitly
unavailable where supporting inputs have not been supplied.

A separate Evidence Pack/deterministic-model clickthrough completed with an
immutable run receipt. Retrieval abstained from claiming an improvement when no
new evidence was found; the model policy routed weak output to analyst review.
This verifies execution and review boundaries, not external-model answer quality.

Observed upload-to-ready times on the final local pass were approximately 41s,
40s and 82s respectively. These single runs share a development machine and are
not a throughput benchmark. An earlier pass reached about 2.69 GiB peak process
working set. Validate resource sizing, responsiveness, queue limits, recovery and
production authentication in the actual deployment.

GitHub retained-copy cleanup and deployment credential-reuse review remain open
publication/security work. A source history rewrite is not proof of retained-copy
removal. See the [release roadmap](../../RELEASE_ROADMAP.md).

The completed JSON summary and a Vesper browser screenshot accompany this report.
The exact commit's automated results are available through
[PR #1](https://github.com/lkjalop/JanuSec/pull/1).
