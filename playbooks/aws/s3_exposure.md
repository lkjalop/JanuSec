Playbook: Exposed S3 Bucket with Sensitive Objects

Trigger:
- Alert: CSPM or connector reports S3 bucket public ACL/policy or S3 Access Logs show anonymous GETs
- GuardDuty or CloudTrail reports unusual access patterns to S3

Immediate containment:
1. Notify bucket owner and on-call infra team.
2. If permitted, apply S3 Block Public Access settings to the bucket immediately (console/API).
3. If the bucket is used by production services, apply a restrictive bucket policy denying public access and allow only service principals.
4. Preserve evidence: copy vulnerable objects to a quarantine bucket with restricted permissions and log the action.

Data collection & enrichment:
- Pull CloudTrail events for the bucket (object-level API calls) for the prior 24-72 hours.
- Fetch S3 access logs for the bucket (or enable them if not present) and collate requester IPs.
- Use S3 Inventory (if available) or list objects to identify sensitive object paths and object metadata.
- Resolve principals via IAM lookup; check for role chaining or unusual confg.

Investigation steps:
- Determine whether objects were read/downloaded: correlate CloudTrail GetObject and S3 access logs with external network egress (VPC Flow Logs) for data exfil.
- If an IAM user/role is implicated, rotate keys and revoke active sessions.
- Check for pre-signed URL issuance events in application logs or CloudTrail.

Remediation & follow-up:
- Tighten bucket policy and implement least-privilege access.
- Enable S3 Block Public Access account-level settings if not already enabled.
- Review application code for accidental public URL generation and remediate.
- Add alerts for any future public ACL/policy changes.
- Document incident timeline, evidence, and applied changes; run a post-mortem.
