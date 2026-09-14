Compliance Evidence Repository Structure

Suggested layout for organizing audit evidence per framework and control.

compliance_evidence/
  iso27001/
    A.5_policies/
    A.8_asset_mgmt/
    A.9_access_control/
    A.12_logging_monitoring/
    A.13_network_security/
    A.14_secure_development/
    A.16_incident_response/

Notes
- Store documents, screenshots, exports, and test results here.
- Use the API `/api/v1/compliance/evidence/upload` to associate files with specific controls.
- The UI shows remediation items; keep evidence links in remediation plans.

