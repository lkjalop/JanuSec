Playbook: VPC Lateral Movement / Suspected Exfil

Trigger:
- VPC Flow Logs or GuardDuty show internal-to-internal suspicious connections or large data egress to external IPs.

Immediate containment:
1. Identify affected subnets and instances; apply restrictive security group rules to block suspicious traffic.
2. Snapshot affected instances (AMIs) and take EBS volume snapshots for forensic analysis.
3. If possible, isolate instances to a remediation subnet or apply Network ACLs.

Evidence collection:
- Pull VPC Flow Logs covering the time window and correlate with CloudTrail and application logs.
- Capture process and network activity from the host (CloudWatch agent, guest agent logs) if available.
- Identify external endpoints and check reputation/ASN.

Investigation & remediation:
- Determine lateral movement path: which host communicated to whom and how credentials were reused.
- If credentials were used, rotate keys and revoke sessions.
- Apply least-privilege IAM changes, re-image compromised hosts, and redeploy from trusted images.

Follow-up:
- Harden host-level logging, enable eBPF/guest telemetry where possible, and add automated rules to detect unusual east-west connections.
