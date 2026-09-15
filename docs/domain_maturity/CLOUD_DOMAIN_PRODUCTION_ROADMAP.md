# Cloud Domain: Production Readiness Roadmap
**Current Maturity: 50% (Beta) → Target: 95% (Production)**

*Generated: 2025-01-08*

---

## Executive Summary

**Current State**: Cloud domain has **10 factors** covering basic CSPM (Cloud Security Posture Management) integration and IAM policy drift. This is insufficient for production-grade cloud security.

**Target State**: **35 factors** covering AWS/Azure/GCP misconfiguration, IAM abuse, serverless security, container security, secrets exposure, and cloud-native attack patterns.

**Business Impact**: 95% of organizations use cloud infrastructure. Cloud breaches cost avg $4.45M (IBM). Without robust cloud security, JanuSec cannot protect modern cloud-native applications.

**Timeline**: 8-10 weeks to implement all 35 factors with multi-cloud testing.

---

## Current Cloud Factors (10 Total)

| Factor ID | Factor Name | Coverage | Evidence File |
|-----------|-------------|----------|---------------|
| ✅ `cloud:iam_policy_drift` | IAM policy changed unexpectedly | Basic | `src/core/event_pipeline/stages/advanced.py` |
| ✅ `cloud:s3_public_access` | S3 bucket made public | Basic | CSPM integration |
| ✅ `cloud:security_group_wide_open` | Security group allows 0.0.0.0/0 | Basic | CSPM integration |
| ✅ `cloud:unencrypted_storage` | Storage without encryption at rest | Basic | CSPM integration |
| ✅ `cloud:cloudtrail_disabled` | CloudTrail logging disabled | Basic | CSPM integration |
| ✅ `cloud:mfa_disabled_root` | Root account without MFA | Basic | CSPM integration |
| ✅ `cloud:unused_iam_role` | IAM role not used in 90+ days | Basic | CSPM integration |
| ✅ `cloud:overly_permissive_role` | IAM role with Admin/* permissions | Basic | CSPM integration |
| ✅ `cloud:public_snapshot` | EBS/RDS snapshot made public | Basic | CSPM integration |
| ✅ `cloud:key_rotation_disabled` | KMS key rotation disabled | Basic | CSPM integration |

**Current Coverage: 10/35 factors (29%)**

---

## Missing Cloud Factors - Production Requirements

### **Category 1: IAM & Identity Abuse (8 Factors)**

#### **Factor 1: `cloud:iam_privilege_escalation`**
- **What It Detects**: IAM user/role gains more permissions than previously held
- **How It Works**: Track IAM policy changes, flag if new permissions added (especially Admin)
- **Why It Matters**: Indicates compromised account or insider threat
- **Risk Weight**: +0.18
- **Implementation**:
  ```python
  # Compare previous_permissions vs current_permissions
  if 'iam:*' in new_permissions and 'iam:*' not in old_permissions:
      factors.append('cloud:iam_privilege_escalation')
  ```
- **Detection Value**: **Critical** - Prevents admin takeover
- **Zero-Day Detection**: Catches novel privilege escalation chains (e.g., PassRole → CreateRole → AttachPolicy)

---

#### **Factor 2: `cloud:iam_user_created_by_non_admin`**
- **What It Detects**: IAM user created by non-administrator account
- **How It Works**: Parse CloudTrail CreateUser event, check if caller has admin permissions
- **Why It Matters**: Indicates compromised account creating backdoor users
- **Risk Weight**: +0.15
- **Implementation**: CloudTrail event filter: `eventName=CreateUser AND userIdentity.type!=Root`
- **Detection Value**: Catches persistence mechanisms
- **Zero-Day Detection**: Identifies novel account hijacking

---

#### **Factor 3: `cloud:assume_role_cross_account_unusual`**
- **What It Detects**: AssumeRole from unexpected external account
- **How It Works**: Track AssumeRole calls, flag if caller account not in whitelist
- **Why It Matters**: Indicates compromised trust relationship
- **Risk Weight**: +0.17
- **Implementation**:
  ```python
  if event['eventName'] == 'AssumeRole':
      external_account = event['requestParameters']['roleArn'].split(':')[4]
      if external_account not in TRUSTED_ACCOUNTS:
          factors.append('cloud:assume_role_cross_account_unusual')
  ```
- **Detection Value**: Catches cross-account breaches
- **Zero-Day Detection**: Identifies supply chain attacks

---

#### **Factor 4: `cloud:iam_access_key_unused_then_active`**
- **What It Detects**: Dormant access key (unused 90+ days) suddenly active
- **How It Works**: Track access key last used date, flag if 90-day gap then activity
- **Why It Matters**: Indicates stolen/leaked credentials
- **Risk Weight**: +0.14
- **Implementation**: Compare lastUsedDate, flag if current_time - lastUsedDate > 90 days
- **Detection Value**: Catches credential theft
- **Zero-Day Detection**: Identifies leaked keys from code repositories

---

#### **Factor 5: `cloud:federated_login_anomalous_source`**
- **What It Detects**: Federated SSO login from unusual country/IP
- **How It Works**: Track federated login source IPs, flag if geolocates to unexpected country
- **Why It Matters**: Indicates compromised SSO credentials
- **Risk Weight**: +0.12
- **Implementation**: Geolocate source IP, compare to user's typical countries
- **Detection Value**: Catches account takeover
- **Zero-Day Detection**: Identifies SSO token theft

---

#### **Factor 6: `cloud:service_account_interactive_login`**
- **What It Detects**: Service account (non-human) logged in via console
- **How It Works**: Check if account tagged as "service" has ConsoleLogin event
- **Why It Matters**: Service accounts should use API keys, not console (indicates compromise)
- **Risk Weight**: +0.16
- **Implementation**:
  ```python
  if account_type == 'service' and event['eventName'] == 'ConsoleLogin':
      factors.append('cloud:service_account_interactive_login')
  ```
- **Detection Value**: Catches lateral movement
- **Zero-Day Detection**: Identifies compromised service accounts

---

#### **Factor 7: `cloud:iam_policy_backdoor`**
- **What It Detects**: IAM policy with suspicious condition (allow if sourceIP != attacker IP)
- **How It Works**: Parse IAM policy JSON, detect "NotIpAddress" conditions
- **Why It Matters**: Allows attacker persistent access while blocking others
- **Risk Weight**: +0.19
- **Implementation**: Parse policy, flag if `Condition: {"NotIpAddress": {...}}`
- **Detection Value**: Catches advanced persistence
- **Zero-Day Detection**: Identifies novel IAM abuse

---

#### **Factor 8: `cloud:sts_token_exfiltration`**
- **What It Detects**: STS temporary token used from multiple geolocations
- **How It Works**: Track STS token usage by IP, flag if >3 countries in 1 hour
- **Why It Matters**: Indicates token stolen and shared
- **Risk Weight**: +0.15
- **Implementation**: Track token → set(countries), alert if len(countries) > 3
- **Detection Value**: Catches token theft
- **Zero-Day Detection**: Identifies novel exfiltration methods

---

### **Category 2: Serverless Security (6 Factors)**

#### **Factor 9: `cloud:lambda_public_url`**
- **What It Detects**: Lambda function with public URL (no auth required)
- **How It Works**: Check Lambda function configuration for public function URL
- **Why It Matters**: Exposes function to internet (RCE, data exfil)
- **Risk Weight**: +0.13
- **Implementation**: Query Lambda API: `GetFunctionUrlConfig`, check `AuthType=NONE`
- **Detection Value**: Catches misconfigurations
- **Zero-Day Detection**: Identifies accidental exposure

---

#### **Factor 10: `cloud:lambda_env_secrets`**
- **What It Detects**: Secrets in Lambda environment variables (not Secrets Manager)
- **How It Works**: Parse Lambda env vars, detect patterns like API_KEY, PASSWORD, SECRET
- **Why It Matters**: Env vars logged, visible in console (secret leak)
- **Risk Weight**: +0.11
- **Implementation**: Regex match `(API_KEY|PASSWORD|SECRET|TOKEN)` in env var names
- **Detection Value**: Catches secrets exposure
- **Zero-Day Detection**: Identifies credential leaks

---

#### **Factor 11: `cloud:lambda_excessive_permissions`**
- **What It Detects**: Lambda function with Admin/* IAM permissions
- **How It Works**: Parse Lambda execution role, check for overly broad permissions
- **Why It Matters**: Compromised function can escalate to full account takeover
- **Risk Weight**: +0.16
- **Implementation**: Check if execution role has `*:*` or `iam:*` permissions
- **Detection Value**: Catches privilege escalation paths
- **Zero-Day Detection**: Identifies blast radius of compromise

---

#### **Factor 12: `cloud:lambda_layer_malicious`**
- **What It Detects**: Lambda layer from untrusted source or with suspicious code
- **How It Works**: Check layer ARN against whitelist, scan layer code for malicious patterns
- **Why It Matters**: Malicious layers can exfiltrate data, create backdoors
- **Risk Weight**: +0.17
- **Implementation**: Extract layer ARN, verify account matches organization, scan for `eval()`, `exec()`
- **Detection Value**: Catches supply chain attacks
- **Zero-Day Detection**: Identifies malicious dependencies

---

#### **Factor 13: `cloud:function_runtime_outdated`**
- **What It Detects**: Lambda using deprecated runtime (Python 2.7, Node 8.x)
- **How It Works**: Check Lambda runtime version against AWS supported runtimes
- **Why It Matters**: Deprecated runtimes have unpatched vulnerabilities
- **Risk Weight**: +0.10
- **Implementation**: Query Lambda `Runtime`, flag if in `DEPRECATED_RUNTIMES` list
- **Detection Value**: Catches vulnerable functions
- **Zero-Day Detection**: Identifies exploitable legacy code

---

#### **Factor 14: `cloud:lambda_vpc_bypass`**
- **What It Detects**: Lambda function removed from VPC (can now access internet freely)
- **How It Works**: Track VPC configuration changes, flag if VPC removed
- **Why It Matters**: Allows data exfiltration, C2 communication
- **Risk Weight**: +0.14
- **Implementation**: Compare previous VPC config vs current, flag if vpcId changed from X to null
- **Detection Value**: Catches network isolation bypass
- **Zero-Day Detection**: Identifies lateral movement

---

### **Category 3: Container & Kubernetes Security (7 Factors)**

#### **Factor 15: `cloud:container_privileged_mode`**
- **What It Detects**: Container running with --privileged flag
- **How It Works**: Parse container config (Docker/K8s), check for privileged=true
- **Why It Matters**: Privileged containers can escape to host
- **Risk Weight**: +0.18
- **Implementation**: Check ECS task definition or K8s pod spec for `privileged: true`
- **Detection Value**: **Critical** - Prevents container escape
- **Zero-Day Detection**: Identifies high-risk deployments

---

#### **Factor 16: `cloud:container_root_user`**
- **What It Detects**: Container running as root (UID 0)
- **How It Works**: Check container user directive in Dockerfile or K8s spec
- **Why It Matters**: Root containers increase blast radius of compromise
- **Risk Weight**: +0.12
- **Implementation**: Parse `USER` directive in Dockerfile, flag if `USER root` or missing
- **Detection Value**: Catches misconfigurations
- **Zero-Day Detection**: Identifies privilege escalation paths

---

#### **Factor 17: `cloud:container_image_unsigned`**
- **What It Detects**: Container image not signed with Docker Content Trust / Notary
- **How It Works**: Check image signature, verify against trusted registries
- **Why It Matters**: Unsigned images can be tampered (supply chain attack)
- **Risk Weight**: +0.13
- **Implementation**: Check image metadata for signature, verify with Notary
- **Detection Value**: Catches supply chain attacks
- **Zero-Day Detection**: Identifies malicious images

---

#### **Factor 18: `cloud:k8s_secrets_in_env`**
- **What It Detects**: Kubernetes secrets mounted as env vars (instead of volume)
- **How It Works**: Parse K8s pod spec, check if secrets used via `env.valueFrom.secretKeyRef`
- **Why It Matters**: Env vars logged, visible in process listing
- **Risk Weight**: +0.10
- **Implementation**: Parse pod spec, flag if `env[].valueFrom.secretKeyRef` exists
- **Detection Value**: Catches secrets exposure
- **Zero-Day Detection**: Identifies credential leaks

---

#### **Factor 19: `cloud:k8s_hostpath_volume`**
- **What It Detects**: Kubernetes pod with hostPath volume mount
- **How It Works**: Parse pod spec, check for `volumes[].hostPath`
- **Why It Matters**: Allows container to access host filesystem (escape path)
- **Risk Weight**: +0.17
- **Implementation**: Check pod spec for `hostPath`, flag if present
- **Detection Value**: **Critical** - Prevents container escape
- **Zero-Day Detection**: Identifies breakout attempts

---

#### **Factor 20: `cloud:k8s_service_account_auto_mount`**
- **What It Detects**: Service account token auto-mounted (default behavior)
- **How It Works**: Check pod spec for `automountServiceAccountToken: false`
- **Why It Matters**: Compromised pod can use token to access K8s API
- **Risk Weight**: +0.11
- **Implementation**: Flag if `automountServiceAccountToken` not set to false
- **Detection Value**: Catches lateral movement
- **Zero-Day Detection**: Identifies K8s API abuse

---

#### **Factor 21: `cloud:k8s_admission_controller_disabled`**
- **What It Detects**: Critical admission controllers disabled (PodSecurityPolicy, NetworkPolicy)
- **How It Works**: Query K8s API server config, check enabled admission controllers
- **Why It Matters**: Disabling security controls allows malicious deployments
- **Risk Weight**: +0.15
- **Implementation**: Check `kube-apiserver` flags for `--enable-admission-plugins`
- **Detection Value**: Catches security control bypass
- **Zero-Day Detection**: Identifies weakened defenses

---

### **Category 4: Secrets & Credentials Exposure (6 Factors)**

#### **Factor 22: `cloud:secrets_manager_unused_secret`**
- **What It Detects**: Secret stored but never accessed in 90+ days
- **How It Works**: Query Secrets Manager `LastAccessedDate`, flag if >90 days
- **Why It Matters**: Unused secrets = forgotten credentials (attack vector)
- **Risk Weight**: +0.08
- **Implementation**: Check `LastAccessedDate`, compare to current_time
- **Detection Value**: Hygiene issue (cleanup reduces attack surface)
- **Zero-Day Detection**: Identifies abandoned credentials

---

#### **Factor 23: `cloud:secrets_manager_rotation_disabled`**
- **What It Detects**: Secret without automatic rotation enabled
- **How It Works**: Check secret configuration for `RotationEnabled=true`
- **Why It Matters**: Long-lived credentials increase compromise window
- **Risk Weight**: +0.09
- **Implementation**: Query `DescribeSecret`, flag if `RotationEnabled=false`
- **Detection Value**: Catches static credentials
- **Zero-Day Detection**: Identifies stale secrets

---

#### **Factor 24: `cloud:parameter_store_plaintext`**
- **What It Detects**: Sensitive parameter stored as String (not SecureString)
- **How It Works**: Query SSM Parameter Store, check if Type=String and name suggests secret
- **Why It Matters**: Plaintext secrets visible to anyone with read access
- **Risk Weight**: +0.12
- **Implementation**:
  ```python
  if param['Type'] == 'String' and any(kw in param['Name'] for kw in ['password', 'key', 'token']):
      factors.append('cloud:parameter_store_plaintext')
  ```
- **Detection Value**: Catches secrets exposure
- **Zero-Day Detection**: Identifies credential leaks

---

#### **Factor 25: `cloud:rds_master_password_weak`**
- **What It Detects**: RDS database with weak master password
- **How It Works**: Attempt to authenticate with common passwords (admin, password123, etc.)
- **Why It Matters**: Weak passwords allow database takeover
- **Risk Weight**: +0.16
- **Implementation**: Try 100 common passwords against RDS endpoint
- **Detection Value**: Catches weak credentials
- **Zero-Day Detection**: Identifies brute-force vulnerabilities

---

#### **Factor 26: `cloud:ec2_metadata_imdsv1`**
- **What It Detects**: EC2 instance using IMDSv1 (not IMDSv2)
- **How It Works**: Check instance metadata service version
- **Why It Matters**: IMDSv1 vulnerable to SSRF attacks (steal credentials)
- **Risk Weight**: +0.13
- **Implementation**: Query instance metadata: `http://169.254.169.254/latest/meta-data/`, check if requires token
- **Detection Value**: Catches SSRF vulnerabilities
- **Zero-Day Detection**: Identifies credential theft paths

---

#### **Factor 27: `cloud:hardcoded_credentials_in_userdata`**
- **What It Detects**: EC2 UserData script contains hardcoded passwords/keys
- **How It Works**: Parse UserData, regex match credential patterns
- **Why It Matters**: UserData visible in console, logged (credential leak)
- **Risk Weight**: +0.14
- **Implementation**: Regex match `(password|api_key|secret)=\w+` in UserData
- **Detection Value**: Catches secrets exposure
- **Zero-Day Detection**: Identifies credential leaks

---

### **Category 5: Data Storage Security (5 Factors)**

#### **Factor 28: `cloud:s3_bucket_versioning_disabled`**
- **What It Detects**: S3 bucket without versioning enabled
- **How It Works**: Check bucket configuration for VersioningConfiguration
- **Why It Matters**: Ransomware can delete data permanently (no recovery)
- **Risk Weight**: +0.10
- **Implementation**: Query `GetBucketVersioning`, flag if Status != 'Enabled'
- **Detection Value**: Catches ransomware risk
- **Zero-Day Detection**: Identifies data loss paths

---

#### **Factor 29: `cloud:s3_bucket_logging_disabled`**
- **What It Detects**: S3 bucket without access logging
- **How It Works**: Check bucket logging configuration
- **Why It Matters**: No audit trail of data access/exfiltration
- **Risk Weight**: +0.08
- **Implementation**: Query `GetBucketLogging`, flag if LoggingEnabled is null
- **Detection Value**: Blind spot for forensics
- **Zero-Day Detection**: Reduces visibility

---

#### **Factor 30: `cloud:rds_snapshot_unencrypted`**
- **What It Detects**: RDS snapshot not encrypted
- **How It Works**: Check snapshot Encrypted attribute
- **Why It Matters**: Snapshot can be copied to attacker account (data theft)
- **Risk Weight**: +0.15
- **Implementation**: Query `DescribeDBSnapshots`, flag if Encrypted=false
- **Detection Value**: Catches data exfiltration paths
- **Zero-Day Detection**: Identifies sensitive data exposure

---

#### **Factor 31: `cloud:dynamodb_pitr_disabled`**
- **What It Detects**: DynamoDB table without Point-in-Time Recovery
- **How It Works**: Check table PointInTimeRecoveryDescription
- **Why It Matters**: Ransomware/malicious deletion cannot be recovered
- **Risk Weight**: +0.09
- **Implementation**: Query `DescribeContinuousBackups`, flag if PointInTimeRecoveryStatus != 'ENABLED'
- **Detection Value**: Catches ransomware risk
- **Zero-Day Detection**: Identifies data loss paths

---

#### **Factor 32: `cloud:ebs_volume_unattached_unencrypted`**
- **What It Detects**: Unattached EBS volume without encryption
- **How It Works**: Check if volume state=available and encrypted=false
- **Why It Matters**: Orphaned volumes contain sensitive data (forgotten, vulnerable)
- **Risk Weight**: +0.11
- **Implementation**: Query `DescribeVolumes`, filter state='available' AND encrypted=false
- **Detection Value**: Catches data remnants
- **Zero-Day Detection**: Identifies sensitive data exposure

---

### **Category 6: Network & Perimeter Security (3 Factors)**

#### **Factor 33: `cloud:vpc_flow_logs_disabled`**
- **What It Detects**: VPC without flow logs enabled
- **How It Works**: Check VPC flow log configuration
- **Why It Matters**: No visibility into network traffic (lateral movement undetected)
- **Risk Weight**: +0.12
- **Implementation**: Query `DescribeFlowLogs`, flag if VPC has no associated flow logs
- **Detection Value**: Blind spot for lateral movement
- **Zero-Day Detection**: Reduces network visibility

---

#### **Factor 34: `cloud:nacl_allow_all_outbound`**
- **What It Detects**: Network ACL allowing all outbound traffic (0.0.0.0/0)
- **How It Works**: Parse NACL egress rules, check for 0.0.0.0/0
- **Why It Matters**: Allows data exfiltration to any destination
- **Risk Weight**: +0.08
- **Implementation**: Query `DescribeNetworkAcls`, flag if egress rule allows 0.0.0.0/0
- **Detection Value**: Catches exfiltration paths
- **Zero-Day Detection**: Identifies overly permissive rules

---

#### **Factor 35: `cloud:igw_attached_private_subnet`**
- **What It Detects**: Internet Gateway attached to subnet marked "private"
- **How It Works**: Check subnet route table for IGW, verify subnet tag is "private"
- **Why It Matters**: Private subnets should not have direct internet access
- **Risk Weight**: +0.13
- **Implementation**: Parse route table, flag if 0.0.0.0/0 → igw-* on private subnet
- **Detection Value**: Catches misconfigurations
- **Zero-Day Detection**: Identifies accidental exposure

---

## Implementation Priority

### **Phase 1 (Weeks 1-2): Critical IAM & Identity**
**Priority: CRITICAL - Prevents account takeover**

1. ✅ `cloud:iam_privilege_escalation` - Admin takeover
2. ✅ `cloud:iam_policy_backdoor` - Persistent access
3. ✅ `cloud:iam_user_created_by_non_admin` - Backdoor accounts
4. ✅ `cloud:assume_role_cross_account_unusual` - Cross-account breach
5. ✅ `cloud:service_account_interactive_login` - Compromised service accounts

**Expected Impact**: 80% reduction in IAM-based attacks

---

### **Phase 2 (Weeks 3-4): Serverless & Container Security**
**Priority: HIGH - Cloud-native attack prevention**

6. ✅ `cloud:lambda_excessive_permissions` - Serverless privilege escalation
7. ✅ `cloud:container_privileged_mode` - Container escape
8. ✅ `cloud:k8s_hostpath_volume` - K8s breakout
9. ✅ `cloud:lambda_layer_malicious` - Supply chain attacks
10. ✅ `cloud:container_image_unsigned` - Tampered images

**Expected Impact**: 70% reduction in cloud-native attacks

---

### **Phase 3 (Weeks 5-7): Secrets & Data Protection**
**Priority: HIGH - Prevents data breaches**

11. ✅ `cloud:ec2_metadata_imdsv1` - SSRF credential theft
12. ✅ `cloud:rds_snapshot_unencrypted` - Data exfiltration
13. ✅ `cloud:parameter_store_plaintext` - Secrets exposure
14. ✅ `cloud:hardcoded_credentials_in_userdata` - Credential leaks
15. ✅ `cloud:lambda_env_secrets` - Secrets in env vars

**Expected Impact**: 85% reduction in secrets exposure

---

### **Phase 4 (Weeks 8-10): Network & Perimeter**
**Priority: MEDIUM - Defense in depth**

16-35. All remaining factors (network security, logging, misconfiguration)

**Expected Impact**: 95% overall cloud security coverage

---

## Testing & Validation

### **Required Test Datasets**

1. **AWS Well-Architected Tool Assessment**
   - Test against AWS security best practices
   - Target: >95% alignment

2. **CIS AWS Foundations Benchmark**
   - 100+ security controls
   - Target: 90% detection coverage

3. **ScoutSuite Cloud Security Scan**
   - Multi-cloud misconfiguration scanner
   - Target: Match/exceed ScoutSuite detection

4. **Production Cloud Environment (Benign)**
   - Scan 1000+ resources (EC2, Lambda, S3, RDS)
   - Target: <2% false positive rate

---

## Success Metrics

### **Detection Metrics**
- **CIS Benchmark Coverage**: 90% (vs. 30% current)
- **IAM Attack Detection**: >95% (vs. 50% current)
- **Serverless Security**: >85% coverage (vs. 20% current)
- **False Positive Rate**: <2%

### **Business Metrics**
- **Cloud Coverage**: 95% (vs. 50% current)
- **Multi-Cloud**: AWS + Azure + GCP support
- **ROI**: Prevent avg $4.45M cloud breach cost

### **Brand Confidence Metrics**
- **Security Professional Trust**: "CIS-compliant cloud security"
- **Executive Confidence**: "Prevents cloud data breaches"
- **Competitive Position**: Match Wiz, Orca Security

---

## Multi-Cloud Support

### **AWS Coverage** (Primary)
- All 35 factors initially built for AWS
- Uses CloudTrail, Config, GuardDuty integration

### **Azure Coverage** (Phase 2)
- Translate factors to Azure equivalents:
  - `cloud:iam_privilege_escalation` → Azure AD role assignment changes
  - `cloud:lambda_excessive_permissions` → Azure Functions RBAC
  - `cloud:s3_public_access` → Blob Storage public access

### **GCP Coverage** (Phase 3)
- Translate factors to GCP equivalents:
  - `cloud:iam_privilege_escalation` → GCP IAM binding changes
  - `cloud:lambda_excessive_permissions` → Cloud Functions IAM
  - `cloud:s3_public_access` → Cloud Storage public access

---

## Integration Requirements

### **AWS Integration**
- **CloudTrail**: Real-time event stream for IAM changes
- **Config**: Resource configuration snapshots
- **GuardDuty**: Threat intelligence integration
- **Security Hub**: CSPM findings correlation

### **Azure Integration**
- **Activity Log**: Azure AD, resource changes
- **Security Center**: CSPM findings
- **Sentinel**: SIEM integration

### **GCP Integration**
- **Cloud Logging**: Audit logs
- **Security Command Center**: CSPM findings
- **Chronicle**: SIEM integration

---

## Why These 35 Factors Matter

### **For Security Professionals**

1. **CIS Alignment**: Maps to CIS AWS/Azure/GCP Benchmarks (industry standard)
2. **Cloud-Native Threats**: Covers serverless, containers, K8s (modern attack surface)
3. **Multi-Cloud**: Single pane of glass across AWS/Azure/GCP
4. **Low False Positives**: Context-aware (legitimate config changes vs. malicious)

### **For Executives**

1. **Breach Prevention**: Cloud breaches cost avg $4.45M (IBM)
2. **Compliance**: CIS Benchmark alignment satisfies auditors (SOC 2, ISO 27001)
3. **Cloud Migration Risk**: Secure cloud adoption (lift-and-shift safely)
4. **Cost Optimization**: Identifies unused resources (secrets, IAM roles)

### **For Platform Credibility**

1. **Industry Standard**: Matches Wiz, Orca, Lacework capabilities
2. **Zero-Day Coverage**: Behavioral analysis (privilege escalation chains, token theft)
3. **Proven Techniques**: Based on CIS, AWS Well-Architected, Azure Security Benchmark
4. **Real-World Validated**: Test against ScoutSuite, Prowler datasets

---

## Competitive Positioning After Implementation

### **Before (Current State)**
- ❌ "Basic CSPM integration"
- ❌ Cannot compete with Wiz, Orca, Lacework
- ❌ Cloud is weak domain (50% coverage)

### **After (Post-Implementation)**
- ✅ "Comprehensive multi-cloud security with behavioral threat detection"
- ✅ Competitive with tier-1 CSPM platforms
- ✅ Cloud becomes strength (95% coverage)
- ✅ Unique: Correlates cloud attacks with endpoint/network (HopGraph chains IAM compromise → Lambda execution → lateral movement)

---

## Zero-Day Detection Capability

### **How These Factors Catch Zero-Days**

**Example: Zero-Day IAM Privilege Escalation**
- Traditional CSPM: ❌ Misses novel escalation chains
- JanuSec: ✅ `cloud:iam_privilege_escalation` (tracks permission changes) + `cloud:iam_user_created_by_non_admin` → Escalation chain detected

**Example: Novel Lambda Backdoor**
- Traditional CSPM: ❌ No signature for unknown malware
- JanuSec: ✅ `cloud:lambda_layer_malicious` (untrusted layer) + `cloud:lambda_env_secrets` (exfiltrated credentials) → Backdoor detected

**Example: K8s Container Escape**
- Traditional CSPM: ❌ Static config check only
- JanuSec: ✅ `cloud:container_privileged_mode` + `cloud:k8s_hostpath_volume` + HopGraph (container → host → lateral movement) → Escape chain reconstructed

---

## Risk Mitigation

### **Implementation Risks**

**Risk 1: Cloud API Rate Limits**
- *Mitigation*: Batch queries, cache results for 5 minutes, use AWS Config snapshots

**Risk 2: Multi-Cloud Complexity**
- *Mitigation*: Phase rollout (AWS first, then Azure, then GCP), reusable factor templates

**Risk 3: False Positives (Legitimate Admin Activity)**
- *Mitigation*: Whitelist known admin IPs, require multiple factors to alert, time-of-day analysis

---

## Conclusion

Implementing these **35 cloud factors** transforms cloud domain from **50% coverage (beta quality)** to **95% coverage (production-ready)**.

**Investment Required**: 8-10 weeks engineering time

**Expected Outcomes**:
- ✅ 90% CIS Benchmark coverage
- ✅ >95% IAM attack detection
- ✅ >85% serverless/container security
- ✅ <2% false positive rate
- ✅ Multi-cloud support (AWS/Azure/GCP)

**Business Impact**: Cloud security becomes **major selling point**. Platform can credibly claim "comprehensive cloud-native security" to security professionals and executives. Correlating cloud attacks with endpoint/network (via HopGraph) provides **unique value** no CSPM vendor offers (Wiz, Orca, Lacework focus on posture, not attack reconstruction).
