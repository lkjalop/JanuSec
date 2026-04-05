JanuSec Information Security Policy

Version: 1.0
Effective Date: 2025-10-28
Owner: Security Team
Review Frequency: Quarterly

1. Purpose
This policy establishes the framework for protecting JanuSec platform assets and customer data.

2. Scope
Applies to all employees, contractors, systems, and third-party integrations handling JanuSec data.

3. Roles and Responsibilities
- Security Officer: Overall accountability for ISMS
- Development Team: Secure coding, vulnerability remediation
- Operations Team: Infrastructure security, monitoring, incident response

4. Asset Classification
- Critical: Customer data, authentication credentials, AI models
- High: Security event logs, SBOM data, compliance evidence
- Medium: System metrics, configuration files
- Low: Public documentation

5. Access Control
- MFA required for all production access
- Quarterly access reviews and documented approvals
- Principle of least privilege and timely offboarding (<=24h)

6. Incident Response
- See docs/runbooks/incident_response.md
- P0: respond <1h; P1: <4h; P2: <24h

7. Change Management
- All production changes require peer review
- Security review for high-risk changes; rollback plan required

8. Compliance
- ISO 27001:2022 certification target: Q2 2026
- SOC 2 Type I audit: Q3 2026; ISO 42001 (AI): Q4 2026

9. Policy Review
Reviewed quarterly by Security Officer. Next review: 2026-01-28.

