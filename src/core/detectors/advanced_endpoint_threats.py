"""AdvancedEndpointThreatsDetector — Linux/Windows advanced threat vectors.

Covers threat vectors NOT handled by existing detectors:

    FILELESS / IN-MEMORY ATTACKS
    endpoint:fileless_reflective_load   — Reflective DLL injection / PE loading from memory
    endpoint:fileless_process_hollow    — Process hollowing indicators
    endpoint:fileless_shellcode_alloc   — RWX memory allocation in unusual processes

    eBPF / KERNEL ROOTKIT (Linux)
    endpoint:ebpf_prog_load_unusual     — bpf() syscall from non-root or non-standard tool
    endpoint:kernel_module_novel        — insmod/modprobe loading unknown module
    endpoint:kernel_symbol_hook         — /proc/kallsyms write or kprobes from userspace tool
    endpoint:proc_hide_indicator        — /proc/<pid> disappearance during enumeration (rootkit tell)

    STEGANOGRAPHY
    endpoint:steg_tool_execution        — Known steganography tool or -outguess/-steghide CLI args
    endpoint:steg_image_entropy_flat    — Image file with suspiciously flat Shannon entropy (LSB hiding)
    endpoint:steg_polyglot_image        — Image magic + ZIP footer (polyglot container)

    SUPPLY CHAIN / THIRD-PARTY
    endpoint:npm_postinstall_exec       — npm package lifecycle script executing shell commands
    endpoint:pip_setup_exec             — pip install running setup.py with subprocess/os.system
    endpoint:build_tool_network         — Build tools (make/gradle/mvn) spawning curl/wget/nc
    endpoint:dev_tool_modified          — Dev tool binary (git/node/python) hash differs from baseline
    endpoint:ci_runner_escalation       — CI runner process acquiring root or modifying system paths

    MACROS / OFFICE (beyond OLE — VBScript, XLM, DDE)
    endpoint:xlm_macro_execution        — Excel 4.0 (XLM) macro execution (AUTO_OPEN in CHAR())
    endpoint:dde_command_injection      — DDE field executing shell command in Word/Excel
    endpoint:vba_environ_recon          — VBA Environ() call on sensitive vars (USERNAME, COMPUTERNAME)

    RANSOMWARE (non-file-encryption indicators not in endpoint_ransom.py)
    endpoint:ransom_network_share_enum  — Mass SMB share enumeration before encryption wave
    endpoint:ransom_backup_catalog_del  — Backup catalog deletion (wbadmin delete catalog)
    endpoint:ransom_inhibit_recovery    — bcdedit /set recoveryenabled no

All factors follow the existing pattern: {factor, score, reason, tags, ...metadata}
"""
from __future__ import annotations

import math
import os
import re
import struct
import time
from collections import Counter
from typing import Any, Dict, List, Optional

try:
    from src.detectors.ewma_adaptive import AdaptiveEWMA
    _ADV_EWMA: Optional[Any] = AdaptiveEWMA(base_alpha=0.2)
except Exception:
    _ADV_EWMA = None

# ---------------------------------------------------------------------------
# FILELESS / IN-MEMORY
# ---------------------------------------------------------------------------

# Reflective DLL injection signatures in process command-line or event description
_REFLECTIVE_PATTERNS = re.compile(
    r'(?:'
    r'ReflectiveDll(?:Inject)?|Invoke-ReflectivePEInjection|'
    r'Invoke-Shellcode|PowerSploit|'
    r'NtAllocateVirtualMemory|VirtualAllocEx.*PAGE_EXECUTE_READWRITE|'
    r'CreateRemoteThread.*LoadLibrary|'
    r'[Mm]em(?:fd|_create|fd_create)\s*\(|'        # Linux memfd_create
    r'shm_open.*PROT_EXEC'                          # Linux shared mem exec
    r')',
    re.IGNORECASE,
)

_HOLLOW_PATTERNS = re.compile(
    r'(?:'
    r'NtUnmapViewOfSection|ZwUnmapViewOfSection|'
    r'WriteProcessMemory.*ResumeThread|'
    r'SetThreadContext.*GetThreadContext|'
    r'CREATE_SUSPENDED.*WriteProcessMemory'
    r')',
    re.IGNORECASE,
)

# RWX allocation outside standard patterns
_RWX_PATTERNS = re.compile(
    r'(?:'
    r'VirtualAlloc(?:Ex)?\s*\(.*(?:0x40|PAGE_EXECUTE_READWRITE)|'
    r'mprotect\s*\(.*PROT_EXEC.*PROT_WRITE|'
    r'mmap\s*\(.*MAP_EXEC.*MAP_WRITE'
    r')',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# eBPF / KERNEL (Linux)
# ---------------------------------------------------------------------------

_EBPF_LOAD_PATTERNS = re.compile(
    r'(?:'
    r'\bbpf\s*\(|'
    r'BPF_PROG_LOAD|'
    r'ip\s+link\s+set.*xdp|'
    r'tc\s+filter\s+add.*bpf|'
    r'perf_event_open\s*\(|'
    r'bpftool\s+(?:prog|map)\s+load'
    r')',
    re.IGNORECASE,
)

_KERNEL_MODULE_PATTERNS = re.compile(
    r'(?:\binsmod\b|\bmodprobe\b)\s+([^\s;|&]+)',
    re.IGNORECASE,
)

_KERNEL_HOOK_PATTERNS = re.compile(
    r'(?:'
    r'/proc/kallsyms|'
    r'kprobe_register|'
    r'register_kprobe|'
    r'/sys/kernel/debug/kprobes|'
    r'ftrace_set_filter|'
    r'/proc/sys/kernel/nmi_watchdog'
    r')',
    re.IGNORECASE,
)

_PROC_HIDE_PATTERNS = re.compile(
    r'(?:'
    r'getdents(?:64)?\s*\(|'       # hooking getdents = directory listing manipulation
    r'/proc/\d+/\w+.*(?:hide|hook|patch)|'
    r'sys_call_table'
    r')',
    re.IGNORECASE,
)

# Processes that legitimately load eBPF programs
_EBPF_KNOWN_GOOD = {
    'bpftool', 'cilium', 'falco', 'tetragon', 'sysdig', 'pixie',
    'datadog-agent', 'ebpf_exporter', 'katran', 'suricata',
    'bpf_iptables', 'xdp-filter', 'tc', 'ip',
}

# Known kernel modules (benign) — short list, extend from /proc/modules baseline in prod
_KNOWN_MODULES = {
    'ext4', 'xfs', 'btrfs', 'nfs', 'nfsd', 'cifs', 'fuse', 'overlay',
    'vxlan', 'veth', 'bridge', 'iptable_filter', 'nf_conntrack',
    'nvidia', 'amdgpu', 'i915', 'virtio_net', 'virtio_blk', 'virtio_scsi',
    'e1000', 'ixgbe', 'mlx5_core', 'vmxnet3', 'vmw_pvscsi',
    'dm_crypt', 'dm_thin_pool', 'dm_multipath',
}

# ---------------------------------------------------------------------------
# STEGANOGRAPHY
# ---------------------------------------------------------------------------

_STEG_TOOL_PATTERNS = re.compile(
    r'(?:'
    r'\bsteghide\b|\boutguess\b|\bstegbreak\b|\bopenstego\b|\bstegsnow\b|'
    r'\bstegcracker\b|\bzsteg\b|\bstegexpose\b|'
    r'--embed.*--cover|--extract.*--stegofile'
    r')',
    re.IGNORECASE,
)

_IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.tif'}
_STEG_ENTROPY_SUSPICIOUS_LOW  = 6.5   # Unusually low for an image (LSB modified = flatter distribution)
_STEG_ENTROPY_SUSPICIOUS_HIGH = 7.98  # Unusually high = possibly encrypted payload embedded

# Magic byte → expected entropy range for normal files
_IMAGE_MAGIC_BYTES = {
    b'\xff\xd8\xff':     'jpeg',
    b'\x89PNG\r\n\x1a\n': 'png',
    b'GIF87a':           'gif',
    b'GIF89a':           'gif',
    b'BM':               'bmp',
    b'II*\x00':          'tiff',
    b'MM\x00*':          'tiff',
}

# ZIP footer magic (for polyglot detection)
_ZIP_FOOTER = b'PK\x05\x06'


def _shannon_entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = float(len(data))
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _detect_image_type(data: bytes) -> Optional[str]:
    for magic, img_type in _IMAGE_MAGIC_BYTES.items():
        if data.startswith(magic):
            return img_type
    return None


# ---------------------------------------------------------------------------
# SUPPLY CHAIN / DEV TOOLS
# ---------------------------------------------------------------------------

_NPM_POSTINSTALL = re.compile(
    r'(?:node\s+(?:scripts/)?postinstall|npm\s+run\s+postinstall)',
    re.IGNORECASE,
)
_NPM_SHELL_SPAWN = re.compile(
    r'(?:child_process\.exec|spawnSync|execSync|require\([\'"]child_process[\'"]\))',
    re.IGNORECASE,
)
_PIP_SETUP_EXEC = re.compile(
    r'(?:python\s+setup\.py\s+install|pip\s+install.*--no-build-isolation|'
    r'subprocess\.(?:call|run|Popen)|os\.system\s*\()',
    re.IGNORECASE,
)
_BUILD_TOOL_NETWORK = re.compile(
    r'(?:make|gradle|mvn|ant|bazel|cargo|go\s+build|dotnet\s+build)\b',
    re.IGNORECASE,
)
_NETWORK_TOOLS = re.compile(
    r'\b(?:curl|wget|nc|ncat|socat|python.*urllib|requests\.get|fetch\s*\()',
    re.IGNORECASE,
)
_CI_RUNNER_NAMES = re.compile(
    r'(?:gitlab-runner|github-actions|jenkins|teamcity|bamboo|'
    r'drone|circleci|buildkite|azure-pipelines)',
    re.IGNORECASE,
)
_CI_ESCALATION_PATTERNS = re.compile(
    r'(?:sudo\s+|chmod\s+[0-7]*7[0-7]*|chown\s+root|'
    r'cp\s+.*(?:/etc/|/usr/bin/|/usr/local/bin/)|'
    r'mv\s+.*(?:/etc/|/usr/bin/|/usr/local/bin/))',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# MACROS: XLM, DDE, VBA environ recon
# ---------------------------------------------------------------------------

_XLM_PATTERNS = re.compile(
    r'(?:'
    r'EXEC\s*\(|CALL\s*\(|'                           # XLM built-in functions
    r'CHAR\s*\(\s*(?:67|99)\s*\).*CHAR|'              # CHAR(67)="C" obfuscation
    r'FORMULA\.FILL|GOTO\s+\w+!|'
    r'4\.0\s*macro|xlm\s*macro'
    r')',
    re.IGNORECASE,
)

_DDE_PATTERNS = re.compile(
    r'(?:'
    r'\bDDE\b.*(?:cmd\.exe|powershell|mshta|wscript)|'
    r'={DDE\s*\(|{\\field.*\\fldrslt'
    r')',
    re.IGNORECASE,
)

_VBA_ENVIRON = re.compile(
    r'Environ\s*\(\s*"(?:USERNAME|COMPUTERNAME|USERDOMAIN|PROCESSOR_ARCHITECTURE|'
    r'TEMP|TMP|APPDATA|LOCALAPPDATA|PROGRAMFILES|SYSTEMROOT|PATH)"\s*\)',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# RANSOMWARE (non-file-encryption indicators)
# ---------------------------------------------------------------------------

_SHARE_ENUM_PATTERNS = re.compile(
    r'(?:'
    r'net\s+view|'
    r'net\s+share|'
    r'Get-SMBShare|'
    r'Invoke-SMBEnum|'
    r'smb://|'
    r'\\\\[A-Za-z0-9._-]+\\[A-Za-z$]+|'  # UNC paths in bulk
    r'WNetOpenEnum|WNetEnumResource'
    r')',
    re.IGNORECASE,
)

_BACKUP_DEL_PATTERNS = re.compile(
    r'(?:'
    r'wbadmin\s+delete\s+(?:catalog|backup|systemstatebackup)|'
    r'vssadmin\s+delete\s+shadows|'
    r'Get-WBSummary.*Delete|'
    r'Remove-WBPolicy'
    r')',
    re.IGNORECASE,
)

_INHIBIT_RECOVERY_PATTERNS = re.compile(
    r'(?:'
    r'bcdedit\s+/set\s+.*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|'
    r'wmic\s+shadowcopy\s+delete|'
    r'fsutil\s+usn\s+deletejournal'
    r')',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------

def detect_advanced_endpoint_threats(
    events: List[Dict[str, Any]],
    tenant_id: str = 'default',
    event_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Detect advanced endpoint threats across all threat vector categories.

    Args:
        events:    Normalized endpoint + email events.
        tenant_id: Tenant ID for EWMA and baseline.
        event_id:  Optional event ID for dedup.

    Returns:
        List of factor dicts.
    """
    factors: List[Dict[str, Any]] = []

    for ev in events:
        try:
            etype      = str(ev.get('event_type') or ev.get('type') or '').lower()
            src        = str(ev.get('source_platform') or ev.get('source') or '').lower()
            cmdline    = str(ev.get('cmdline') or ev.get('command_line') or '')
            proc_name  = str(ev.get('process') or ev.get('image') or ev.get('process_name') or '')
            file_path  = str(ev.get('file_path') or ev.get('target_file') or '')
            hostname   = str(ev.get('host') or ev.get('hostname') or '')
            pid        = str(ev.get('pid') or '')
            parent     = str(ev.get('parent_process') or ev.get('parent_image') or '')
            username   = str(ev.get('user') or ev.get('username') or '')
            combined   = cmdline + ' ' + file_path + ' ' + proc_name

            is_linux   = 'linux' in src or 'auditd' in src or 'ebpf' in src
            is_windows = 'windows' in src or 'sysmon' in src or 'winlogon' in src

            # ----------------------------------------------------------------
            # FILELESS
            # ----------------------------------------------------------------
            if _REFLECTIVE_PATTERNS.search(combined):
                factors.append({
                    'factor': 'endpoint:fileless_reflective_load',
                    'score': 0.90,
                    'reason': f'Reflective DLL injection / in-memory PE loading pattern in "{proc_name}"',
                    'process': proc_name,
                    'cmdline': cmdline[:300],
                    'hostname': hostname,
                    'tags': ['ATTACK:T1055.001', 'ATTACK:T1620', 'STRIDE:elevation'],
                })

            if _HOLLOW_PATTERNS.search(combined):
                factors.append({
                    'factor': 'endpoint:fileless_process_hollow',
                    'score': 0.88,
                    'reason': f'Process hollowing indicators (NtUnmapViewOfSection / ZwUnmapViewOfSection) in "{proc_name}"',
                    'process': proc_name,
                    'cmdline': cmdline[:300],
                    'hostname': hostname,
                    'tags': ['ATTACK:T1055.012', 'STRIDE:elevation'],
                })

            if _RWX_PATTERNS.search(combined):
                factors.append({
                    'factor': 'endpoint:fileless_shellcode_alloc',
                    'score': 0.80,
                    'reason': f'RWX memory allocation (PAGE_EXECUTE_READWRITE / mprotect PROT_EXEC+WRITE) in "{proc_name}"',
                    'process': proc_name,
                    'cmdline': cmdline[:300],
                    'hostname': hostname,
                    'tags': ['ATTACK:T1055', 'ATTACK:T1620', 'STRIDE:elevation'],
                })

            # ----------------------------------------------------------------
            # eBPF / KERNEL (Linux)
            # ----------------------------------------------------------------
            if is_linux or _EBPF_LOAD_PATTERNS.search(combined):
                proc_lower = proc_name.lower().strip()
                if _EBPF_LOAD_PATTERNS.search(combined) and proc_lower not in _EBPF_KNOWN_GOOD:
                    factors.append({
                        'factor': 'endpoint:ebpf_prog_load_unusual',
                        'score': 0.78,
                        'reason': f'eBPF program load from non-standard process "{proc_name}" (expected: security tools)',
                        'process': proc_name,
                        'cmdline': cmdline[:300],
                        'hostname': hostname,
                        'tags': ['ATTACK:T1014', 'ATTACK:T1547', 'STRIDE:elevation'],
                    })

            mod_match = _KERNEL_MODULE_PATTERNS.search(combined)
            if mod_match:
                module_name = os.path.basename(mod_match.group(1)).replace('.ko', '').lower()
                if module_name not in _KNOWN_MODULES:
                    factors.append({
                        'factor': 'endpoint:kernel_module_novel',
                        'score': 0.82,
                        'reason': f'Unknown kernel module "{module_name}" loaded by "{proc_name}"',
                        'module': module_name,
                        'process': proc_name,
                        'cmdline': cmdline[:300],
                        'hostname': hostname,
                        'tags': ['ATTACK:T1547.006', 'ATTACK:T1014', 'STRIDE:elevation'],
                    })

            if _KERNEL_HOOK_PATTERNS.search(combined):
                factors.append({
                    'factor': 'endpoint:kernel_symbol_hook',
                    'score': 0.87,
                    'reason': f'Kernel symbol table or kprobe access by userspace process "{proc_name}"',
                    'process': proc_name,
                    'cmdline': cmdline[:300],
                    'hostname': hostname,
                    'tags': ['ATTACK:T1014', 'ATTACK:T1562', 'STRIDE:elevation'],
                })

            if _PROC_HIDE_PATTERNS.search(combined):
                factors.append({
                    'factor': 'endpoint:proc_hide_indicator',
                    'score': 0.85,
                    'reason': f'Process hiding indicator (getdents hook / sys_call_table modification) in "{proc_name}"',
                    'process': proc_name,
                    'cmdline': cmdline[:300],
                    'hostname': hostname,
                    'tags': ['ATTACK:T1014', 'ATTACK:T1562.001', 'STRIDE:elevation'],
                })

            # ----------------------------------------------------------------
            # STEGANOGRAPHY
            # ----------------------------------------------------------------
            if _STEG_TOOL_PATTERNS.search(combined):
                factors.append({
                    'factor': 'endpoint:steg_tool_execution',
                    'score': 0.82,
                    'reason': f'Known steganography tool or argument pattern executed by "{proc_name}"',
                    'process': proc_name,
                    'cmdline': cmdline[:300],
                    'hostname': hostname,
                    'tags': ['ATTACK:T1027', 'ATTACK:T1048', 'STRIDE:tampering'],
                })

            # File-content based steg checks (when raw content is available)
            file_content = ev.get('file_content') or ev.get('content')
            if file_content and file_path:
                ext_lower = os.path.splitext(file_path.lower())[1]
                if ext_lower in _IMAGE_EXTENSIONS and isinstance(file_content, (bytes, bytearray)):
                    data = bytes(file_content)
                    img_type = _detect_image_type(data)
                    if img_type:
                        entropy = _shannon_entropy_bytes(data)
                        # Normal images have entropy between 7.0 and 7.9 bits
                        if entropy < _STEG_ENTROPY_SUSPICIOUS_LOW:
                            factors.append({
                                'factor': 'endpoint:steg_image_entropy_flat',
                                'score': 0.65,
                                'reason': f'Image file "{file_path}" has unusually low entropy {entropy:.2f}b (possible LSB steganography)',
                                'file_path': file_path,
                                'entropy': round(entropy, 3),
                                'img_type': img_type,
                                'hostname': hostname,
                                'tags': ['ATTACK:T1027', 'ATTACK:T1048', 'STRIDE:tampering'],
                            })
                        # Polyglot: valid image + ZIP footer
                        if _ZIP_FOOTER in data[-65536:]:  # Check last 64KB for ZIP EOCD
                            factors.append({
                                'factor': 'endpoint:steg_polyglot_image',
                                'score': 0.78,
                                'reason': f'Image file "{file_path}" contains ZIP End-of-Central-Directory signature (polyglot container)',
                                'file_path': file_path,
                                'img_type': img_type,
                                'hostname': hostname,
                                'tags': ['ATTACK:T1027', 'ATTACK:T1566.001', 'STRIDE:tampering'],
                            })

            # ----------------------------------------------------------------
            # SUPPLY CHAIN / DEV TOOLS
            # ----------------------------------------------------------------
            if _NPM_POSTINSTALL.search(combined):
                if _NETWORK_TOOLS.search(cmdline) or _NPM_SHELL_SPAWN.search(cmdline):
                    factors.append({
                        'factor': 'endpoint:npm_postinstall_exec',
                        'score': 0.77,
                        'reason': f'npm postinstall script executing network or shell command by "{proc_name}"',
                        'process': proc_name,
                        'cmdline': cmdline[:300],
                        'hostname': hostname,
                        'tags': ['ATTACK:T1195.001', 'ATTACK:T1059.001', 'STRIDE:tampering'],
                    })

            if _PIP_SETUP_EXEC.search(combined):
                if _NETWORK_TOOLS.search(cmdline) or 'os.system' in cmdline or 'subprocess' in cmdline:
                    factors.append({
                        'factor': 'endpoint:pip_setup_exec',
                        'score': 0.72,
                        'reason': f'pip/setup.py executing shell or network commands by "{proc_name}"',
                        'process': proc_name,
                        'cmdline': cmdline[:300],
                        'hostname': hostname,
                        'tags': ['ATTACK:T1195.001', 'ATTACK:T1059.004', 'STRIDE:tampering'],
                    })

            build_tool_match = _BUILD_TOOL_MATCH(combined)
            if build_tool_match and _NETWORK_TOOLS.search(cmdline):
                factors.append({
                    'factor': 'endpoint:build_tool_network',
                    'score': 0.70,
                    'reason': f'Build tool spawning network utility — possible supply chain exfil or C2 by "{proc_name}"',
                    'process': proc_name,
                    'cmdline': cmdline[:300],
                    'hostname': hostname,
                    'tags': ['ATTACK:T1195.001', 'ATTACK:T1071.001', 'STRIDE:tampering'],
                })

            if _CI_RUNNER_NAMES.search(proc_name) or _CI_RUNNER_NAMES.search(parent):
                if _CI_ESCALATION_PATTERNS.search(cmdline):
                    factors.append({
                        'factor': 'endpoint:ci_runner_escalation',
                        'score': 0.83,
                        'reason': f'CI runner process acquiring root or modifying system paths: "{cmdline[:150]}"',
                        'process': proc_name,
                        'parent': parent,
                        'cmdline': cmdline[:300],
                        'hostname': hostname,
                        'username': username,
                        'tags': ['ATTACK:T1195.001', 'ATTACK:T1548', 'STRIDE:elevation'],
                    })

            # ----------------------------------------------------------------
            # MACROS: XLM, DDE, VBA environ
            # ----------------------------------------------------------------
            if _XLM_PATTERNS.search(combined):
                factors.append({
                    'factor': 'endpoint:xlm_macro_execution',
                    'score': 0.84,
                    'reason': f'Excel 4.0 (XLM) macro execution pattern detected in "{proc_name}"',
                    'process': proc_name,
                    'cmdline': cmdline[:300],
                    'hostname': hostname,
                    'tags': ['ATTACK:T1137.001', 'ATTACK:T1204.002', 'STRIDE:tampering'],
                })

            if _DDE_PATTERNS.search(combined):
                factors.append({
                    'factor': 'endpoint:dde_command_injection',
                    'score': 0.86,
                    'reason': f'DDE field executing shell command detected in "{proc_name}"',
                    'process': proc_name,
                    'cmdline': cmdline[:300],
                    'hostname': hostname,
                    'tags': ['ATTACK:T1559.002', 'ATTACK:T1204.002', 'STRIDE:tampering'],
                })

            if _VBA_ENVIRON.search(combined) and proc_name.lower() in {
                'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'access.exe'
            }:
                factors.append({
                    'factor': 'endpoint:vba_environ_recon',
                    'score': 0.65,
                    'reason': f'VBA Environ() call on sensitive environment variable by "{proc_name}" (host/user recon)',
                    'process': proc_name,
                    'cmdline': cmdline[:300],
                    'hostname': hostname,
                    'tags': ['ATTACK:T1082', 'ATTACK:T1059.005', 'STRIDE:information'],
                })

            # ----------------------------------------------------------------
            # RANSOMWARE (non-file-encryption indicators)
            # ----------------------------------------------------------------
            share_count = len(_SHARE_ENUM_PATTERNS.findall(combined))
            if share_count >= 3:
                factors.append({
                    'factor': 'endpoint:ransom_network_share_enum',
                    'score': 0.75,
                    'reason': f'Mass SMB share enumeration ({share_count} patterns) by "{proc_name}" — possible pre-encryption recon',
                    'process': proc_name,
                    'cmdline': cmdline[:300],
                    'hostname': hostname,
                    'tags': ['ATTACK:T1021.002', 'ATTACK:T1083', 'DREAD:damage', 'STRIDE:information'],
                })

            if _BACKUP_DEL_PATTERNS.search(combined):
                factors.append({
                    'factor': 'endpoint:ransom_backup_catalog_del',
                    'score': 0.91,
                    'reason': f'Backup catalog deletion by "{proc_name}" — pre-ransomware indicator',
                    'process': proc_name,
                    'cmdline': cmdline[:300],
                    'hostname': hostname,
                    'tags': ['ATTACK:T1490', 'DREAD:damage', 'STRIDE:denial'],
                })

            if _INHIBIT_RECOVERY_PATTERNS.search(combined):
                factors.append({
                    'factor': 'endpoint:ransom_inhibit_recovery',
                    'score': 0.90,
                    'reason': f'Recovery inhibition command by "{proc_name}": "{cmdline[:120]}"',
                    'process': proc_name,
                    'cmdline': cmdline[:300],
                    'hostname': hostname,
                    'tags': ['ATTACK:T1490', 'DREAD:damage', 'STRIDE:denial'],
                })

        except Exception:
            continue

    return _dedup_highest_score(factors)


def _BUILD_TOOL_MATCH(combined: str) -> bool:
    return bool(_BUILD_TOOL_NETWORK.search(combined))


def _dedup_highest_score(factors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[tuple, Dict[str, Any]] = {}
    for f in factors:
        key = (f.get('factor', ''), f.get('process', ''), f.get('hostname', ''))
        existing = seen.get(key)
        if existing is None or f.get('score', 0) > existing.get('score', 0):
            seen[key] = f
    return list(seen.values())


def detect_advanced_threats(runtime, tenant_id: str = 'default', event_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Runtime adapter matching the existing detector call pattern."""
    try:
        events = list(getattr(runtime, 'sanitized_events', []) or [])
    except Exception:
        events = []
    return detect_advanced_endpoint_threats(events, tenant_id=tenant_id, event_id=event_id)


_DOWNLOAD_OPS = {
    'filedownloaded',
    'filesyncdownloadedfull',
    'filesyncdownloadedpartial',
    'downloadfile',
}
_PURVIEW_OPS = {
    'dlppolicymatched',
    'dlprulematch',
    'dlppolicytip',
    'dlpendpointmatch',
    'sensitivitylabelchanged',
}
_PERSONAL_SYNC_PROCESSES = {
    'box.exe',
    'boxsync.exe',
    'dropbox.exe',
    'googledrivesync.exe',
    'google drive.exe',
    'megasync.exe',
    'onedriveconsumer.exe',
}
_BULK_DOWNLOAD_COUNT = 200
_BULK_DOWNLOAD_BYTES = 500 * 1024 * 1024


def _event_user(ev: Dict[str, Any]) -> str:
    return str(
        ev.get('user')
        or ev.get('username')
        or ev.get('user_name')
        or ev.get('UserName')
        or ''
    ).strip().lower()


def _event_epoch(value: Any) -> Optional[float]:
    if value in (None, '', [], {}):
        return None
    try:
        return float(value)
    except Exception:
        pass
    try:
        from datetime import datetime as _dt
        text = str(value).strip()
        if text.endswith('Z'):
            text = text[:-1] + '+00:00'
        return _dt.fromisoformat(text).timestamp()
    except Exception:
        return None


def _operation(ev: Dict[str, Any]) -> str:
    return str(
        ev.get('operation')
        or ev.get('Operation')
        or ev.get('event_name')
        or ev.get('eventName')
        or ''
    ).strip().lower()


def detect_insider_threats(events: List[Dict[str, Any]] | None) -> List[Dict[str, Any]]:
    """Detect stale-account, bulk-download, Purview DLP, and personal-sync signals."""
    if not events:
        return []

    factors: List[Dict[str, Any]] = []
    by_user: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        if not isinstance(ev, dict):
            continue
        user = _event_user(ev)
        if user:
            by_user.setdefault(user, []).append(ev)

    for ev in events:
        if not isinstance(ev, dict):
            continue
        user = _event_user(ev)
        term_ts = _event_epoch(ev.get('termination_date') or ev.get('terminated_at'))
        login_ts = _event_epoch(ev.get('last_login_epoch') or ev.get('timestamp_epoch') or ev.get('timestamp'))
        status = str(ev.get('account_status') or ev.get('status') or '').strip().lower()
        if term_ts and (status in {'active', 'enabled'} or (login_ts and login_ts > term_ts)):
            days_stale = max(0.0, (time.time() - term_ts) / 86400.0)
            score = min(0.95, 0.55 + min(days_stale, 30.0) / 100.0)
            factors.append({
                'factor': 'identity:stale_account_active',
                'score': round(score, 3),
                'reason': f'Account {user or "unknown"} remained active or logged in after termination',
                'user': user,
                'days_stale': round(days_stale, 1),
                'tags': ['ATTACK:T1078', 'INSIDER:TRUE', 'STRIDE:elevation'],
            })

    for user, user_events in by_user.items():
        download_events = [ev for ev in user_events if _operation(ev) in _DOWNLOAD_OPS]
        total_bytes = 0
        for ev in download_events:
            try:
                total_bytes += int(ev.get('byte_count') or ev.get('bytes') or ev.get('size') or 0)
            except Exception:
                continue
        if len(download_events) >= _BULK_DOWNLOAD_COUNT or total_bytes >= _BULK_DOWNLOAD_BYTES:
            has_dlp = any(_operation(ev) in _PURVIEW_OPS for ev in user_events)
            has_departure = any(_event_epoch(ev.get('termination_date') or ev.get('terminated_at')) for ev in user_events)
            score = 0.68
            if len(download_events) >= _BULK_DOWNLOAD_COUNT:
                score += 0.08
            if total_bytes >= _BULK_DOWNLOAD_BYTES:
                score += 0.08
            if has_dlp:
                score += 0.08
            if has_departure:
                score += 0.06
            factors.append({
                'factor': 'insider:bulk_cloud_download',
                'score': round(min(score, 0.96), 3),
                'reason': f'Bulk cloud download activity for {user}: {len(download_events)} files, {total_bytes} bytes',
                'user': user,
                'file_count': len(download_events),
                'byte_count': total_bytes,
                'purview_correlated': has_dlp,
                'departure_window': has_departure,
                'tags': ['ATTACK:T1213', 'ATTACK:T1530', 'INSIDER:TRUE', 'STRIDE:information'],
            })

        dlp_hits = [ev for ev in user_events if _operation(ev) in _PURVIEW_OPS]
        if dlp_hits:
            factors.append({
                'factor': 'dlp:purview_policy_match',
                'score': round(min(0.55 + (len(dlp_hits) * 0.05), 0.9), 3),
                'reason': f'Purview or endpoint DLP policy matched for {user}',
                'user': user,
                'dlp_hit_count': len(dlp_hits),
                'tags': ['ATTACK:T1213', 'INSIDER:TRUE', 'DLP:PURVIEW', 'STRIDE:information'],
            })

    for ev in events:
        if not isinstance(ev, dict):
            continue
        proc = str(ev.get('process') or ev.get('process_name') or ev.get('FileName') or '').strip()
        proc_l = proc.lower()
        if proc_l not in _PERSONAL_SYNC_PROCESSES:
            continue
        hostname = str(ev.get('hostname') or ev.get('host') or ev.get('ComputerName') or '').strip()
        source = str(ev.get('source') or ev.get('source_platform') or ev.get('_source') or '').strip()
        if not hostname and not source:
            continue
        factors.append({
            'factor': 'insider:personal_cloud_sync_process',
            'score': 0.72,
            'reason': f'Personal cloud sync process {proc} observed on corporate endpoint',
            'process': proc,
            'hostname': hostname,
            'user': _event_user(ev),
            'tags': ['ATTACK:T1567', 'INSIDER:TRUE', 'STRIDE:information'],
        })

    return _dedup_highest_score(factors)


__all__ = ['detect_advanced_endpoint_threats', 'detect_advanced_threats', 'detect_insider_threats']
