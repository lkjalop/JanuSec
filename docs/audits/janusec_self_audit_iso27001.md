JanuSec Self-Audit — ISO/IEC 27001:2022 (Checklist)

Scope: Internal readiness assessment of the JanuSec platform and operations.

ISO 27001:2022 Key Controls (sample)
- A.5 Information Security Policies
  - [ ] A.5.1: InfoSec policy documented (docs/security/information_security_policy.md)
  - [ ] A.5.2: Policy review cadence defined (quarterly)
  - Evidence: policy, acceptable use, risk mgmt framework
- A.8 Asset Management
  - [ ] A.8.1: Asset inventory maintained (docker-compose.yml; cloud IaC; requirements.txt)
  - [ ] A.8.2: Ownership and classification assigned
  - [ ] A.8.3: Retention policy documented
- A.9 Access Control
  - [ ] A.9.1: Access control policy (RBAC, least privilege)
  - [ ] A.9.2: User access mgmt: MFA for prod access; quarterly access reviews
  - [ ] A.9.4: System and application access control
- A.12.4 Logging and Monitoring
  - [ ] Centralized logging; retention >= 90 days
  - [ ] Log integrity and SIEM integration
- A.13 Network Security
  - [ ] Segmentation; NSGs/firewalls documented; zero trust principles
- A.14.2 Secure Development
  - [ ] SDLC policy; code review; SBOM vuln scanning; CI security gates
- A.16.1 Incident Response
  - [ ] IR plan; severity classification; escalation and PIR

Notes
- Use the Compliance UI to upload evidence and generate a gap report.
- Track remediation items using the Remediation Tracker.
