## eBPF Kernel Triage Runbook

Purpose: help analysts triage kernel-level alerts produced by eBPF programs, Falco, or network devices and map findings to mitigation actions, threat models (MITRE, STRIDE), severity scoring (DREAD/CVSS), KEV/MAESTRO tags, and required logs for investigation.

1) Immediate triage steps
- **Confirm program/source**: eBPF, Falco rule, Cisco sensor, or other. Note program version and host kernel.
- **Collect artifacts**: program verifier logs, dmesg, /var/log/syslog, container runtime logs, k8s audit logs, process list, syscall traces.
- **Isolate if high confidence**: if kernel rootkits or suspicious hooking present, isolate node from cluster network via CNI policy and cordon node.

2) Mapping to models
- **MITRE**: map to ATT&CK technique IDs (e.g., T1204, T1547, T1218) — see `detections/ebpf_rules.yaml` for suggested mappings.
- **STRIDE**: label as Spoofing/Tampering/Repudiation/Information disclosure/Denial/Elevation depending on the syscall & target (e.g., credential read => Confidentiality). 
- **DREAD/CVSS**: compute preliminary severity using presence of exploitability indicators (verifier rejects, unknown kprobe attach to sensitive syscalls) and asset criticality.
- **KEV/MAESTRO**: tag findings when known CVE/KEV candidates present in observed binaries or behavior patterns.

3) Suggested logs to collect
- Kernel logs: `dmesg`, `journalctl -k`.
- eBPF verifier logs (capture the verifier output from loader).
- Syscall-level traces for suspect PIDs (via `bcc`/`bpftrace` or `strace` for a short window).
- Container runtime logs and image metadata (image digest, SBOM if available).
- K8s audit logs and network policy events.

4) Enrichment and correlation
- Enrich events with: host owner, pod labels, image digest, process ancestry, network peers, ASN, and known KEV/CVEs affecting loaded modules.
- Correlate across signals: eBPF attach errors + unusual `execve` rates + outbound connections to rare ASNs -> escalate.

5) Playbook suggestions
- Low confidence: add watchlist, increase sampling, attach ephemeral BPF probe to collect syscall args for 10s.
- Medium: snapshot host (procfs, memory), create incident ticket, notify owner, require manual validation before remediation.
- High: cordon/evacuate node, revoke keys, rotate credentials, perform full forensic capture.

6) Notes on false positives
- Many eBPF programs and security agents attach to common syscalls; reduce FP by requiring behavioral anomalies (surge in events, unusual args, cross-host correlation) before high-severity tagging.

7) Example commands
- Dump verifier output (from loader): `sudo dmesg | tail -n 200`
- Short bpftrace capture: `sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%s %s\n", comm, str(args->argv[0])); }' -c 10s`

Appendix: See `detections/ebpf_rules.yaml` for mapping examples.
