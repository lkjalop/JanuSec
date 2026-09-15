# Synthetic telemetry corpora

VESPER, Meridian and Santos are adversarial/sanctioned-activity test scenarios.
The names, identities, organizations, addresses and activity describe fixtures;
they are not claims about real incidents or named organizations. Do not contact
addresses, resolve indicators or execute commands contained in these records.

These copies were promoted from the local acceptance material without modifying
or deleting the user-owned dump directory. `manifest.json` records their byte
hashes. Expected detections and explicit known gaps live in
`tests/fixtures/ground_truth/`. The gate strips annotation fields before detection.
The VESPER source handoff explicitly identifies its telemetry as synthetic.

Passing these corpora does not measure production recall or false-positive rates.
