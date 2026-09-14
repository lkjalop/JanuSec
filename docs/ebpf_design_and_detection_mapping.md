Janusec eBPF Design & Detection Mapping
=====================================

Overview
--------
This document outlines a practical eBPF-based kernel-level detection architecture for Janusec, mapping low-level signals to normalized detection factors and then to MITRE, STRIDE, DREAD, CVSS, and business-impact scoring.

Goals
-----
- Low-overhead, CO-RE eBPF probes that provide high-fidelity signals for containerized workloads.
- Userspace agent to read ring buffers, enrich with container/K8s metadata, normalize to `DetectionFactor` schema, and forward to Janusec ingestion.
- On-demand log pulls and triage rules (e.g., missing Root CA use) that can elevate eBPF evidence to active investigations.

Architecture
------------
1. eBPF program (CO-RE) compiled to .o, attached to tracepoints/kprobes.
2. Userspace agent (Rust/Go/Python) consumes perf ring buffer or BPF_MAP, batches and normalizes events, adds container metadata (cgroup, pod, namespace), calculates preliminary risk score.
3. Ingestion API receives normalized events and stores them in HopGraph with correlation keys (host, container_id, process_hash, file_hash, network_tuple).
4. Correlation and scoring pipeline enriches with intel (ASN, domain reputation), maps to MITRE techniques, calculates CVSS/DREAD-like scores and produces incident suggestions.

Event Types & Probes
--------------------
- execve / process create: capture cmdline, argv0, parent PID/comm, container cgroup.
- file write/create to sensitive paths: /etc/passwd, /var/run/docker.sock, /proc/*/mem, /proc/*/ns.
- network connect: capture dest IP/port, sockfd, UID, cgroup.
- ptrace/process_vm_writev/process_vm_readv: detect process injection.
- namespaces changes / setns calls.
- open of docker.sock or kube secrets path.
- capabilities changed (capset), setuid/setgid.
- bpf map operations and suspicious use of `bpf()` syscall (indicator of self-modifying or kernel map manipulation).
- unusual /proc reads across PIDs or mount namespace boundaries.

Normalization Fields (DetectionFactor schema)
----------------------------------------------
- `source`: host-agent-id
- `sensor`: ebpf
- `event_type`: exec,file_write,network_connect,ptrace,open_socket,namespace_enter
- `ts`: epoch
- `pid`, `ppid`, `comm`, `cmdline`
- `container_id`, `k8s_pod`, `k8s_ns`, `cgroup_path`
- `uid`, `gid`, `selinux_ctx` (if available)
- `path`, `flags`, `ip_dst`, `port_dst`, `proto`
- `evidence`: raw payload trimmed
- `confidence`: heuristic score (0-1)

Detection Examples & Mapping
----------------------------
- Container escape (sequence: spawn pivot process, write to /var/run/docker.sock, perform setns on host ns): map to MITRE T1055 (Process Injection), T1218 (Signed Binary Proxy), STRIDE: Tampering/Privilege Escalation.
- Process injection (ptrace or process_vm_writev targeting PID with different UID): MITRE T1055. DREAD: Damage (High if root process), Reproducibility (Medium), Exploitability (High), Affected Users (High), Discoverability (Medium). CVSS components: High for privileges required.
- Suspicious BPF map writes that modify kernel hooks: MITRE T1609 (Supply Chain/Kernel modifications), STRIDE: Tampering.

Correlating Missing Root CA Use
-------------------------------
- When agents detect outbound TLS connections (via network connect + TLS client hello detection at userspace or TLS fingerprint DB) that do not validate using expected enterprise root CA, flag as `missing_root_ca`.
- Correlate `missing_root_ca` with: sudden exfil network connections, new process spawns in containers, unexpected file reads of credential stores, and anomalous DNS behavior.
- If eBPF shows a process creating encrypted connections while not using host root CA store (or using ephemeral certs), raise to high-priority investigation.

On-Demand Log Pull Integration
------------------------------
- Userspace agent keeps a local ring buffer file/queue of recent events; on-demand pull endpoint requests N minutes of eBPF events for a container or host.
- Pulls are signed and transmitted over TLS to protect chain of custody.
- Pull includes metadata: agent_version, kernel_version, cgroup, sequence numbers, and a proof HMAC computed using agent key.

Triage Rules & Automated Actions
-------------------------------
- If `missing_root_ca` AND `network_connect` to rare ASN AND `execve` of suspicious binary → escalate to Tier-2 autogen, snapshot container, and optionally quarantine (policy-gated).
- If `ptrace` or `process_vm_writev` observed against a system process, create an incident with severity `critical` and recommend immediate isolation for the host.

Next Steps (implementation plan)
--------------------------------
- Implement CO-RE eBPF skeleton and minimal userspace consumer (simulator mode) to produce normalized JSON events.
- Add ingestion API endpoint `/api/v1/ingest/ebpf` to accept batched normalized events (signed) and store in session layer.
- Implement missing-root-CA detector in ingestion pipeline.
- Add correlation rules and scoring function mapping detections to MITRE/DREAD/CVSS.

Appendix: Risk Scoring Heuristic
-------------------------------
- Start with a weighted linear model that maps detection features (privilege required, data access, network exfil, intel match, diversity of indicators) to a 0-100 risk score.
- Calibrate weights with labelled incidents over time and expose override sliders in admin UI.
