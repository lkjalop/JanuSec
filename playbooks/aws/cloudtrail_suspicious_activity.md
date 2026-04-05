Playbook: Suspicious CloudTrail Activity (Privilege Escalation / Role Chaining)

Trigger:
- Unexpected `iam:CreateRole`, `iam:AttachRolePolicy`, `sts:AssumeRole` from non-admin principals
- Rapid sequence of privilege-related API calls across accounts

Immediate containment:
1. Revoke/disable implicated user credentials and active sessions.
2. Remove or restrict recently-created roles/policies pending investigation.
3. If cross-account role assumption is used, rotate trust policies and restrict the monitoring account.

Evidence collection:
- Export CloudTrail events surrounding the principal (48-72 hours before/after).
- Gather IAM policy changes, creation events, and resource ARNs involved.
- Collect environment logs (CloudWatch application logs) and correlate with the events.

Investigation steps:
- Track role chaining by following `AssumeRole` events across account IDs; build a chain timeline.
- Identify any created access keys and rotate them.
- If a principal used an application account, check for leaked secrets or compromised CI/CD credentials.

Remediation:
- Revoke temporary credentials and rotate long-lived keys.
- Apply least-privilege to the implicated roles and add inline deny where required.
- Implement additional monitoring and automation: alert on new `iam:Create*` actions, require approvals.

Follow-up:
- Conduct a thorough audit of all change events and timeline; implement guardrails (policy change reviews) and training.
