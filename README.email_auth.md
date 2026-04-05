Email auth & risk helpers

Development notes:
- DKIM verification: install `dkimpy` (pip install dkimpy)
- DNS lookups for DMARC: install `dnspython` (pip install dnspython)

Files:
- `src/core/email_auth.py`: DKIM/DMARC/ARC helpers
- `src/core/risk_score.py`: risk composition engine

CI: add `dkimpy` and `dnspython` to your dev requirements to enable tests that verify DKIM/DMARC.
