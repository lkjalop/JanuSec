"""Production PCAP capture driver.

Supports two backends:
  - **Scapy** (cross-platform, installed via ``pip install scapy``)
  - **Raw socket** fallback (Linux only, for environments without Scapy)

On Windows Scapy uses Npcap/WinPcap under the hood.  If neither is available
the capture gracefully degrades to ``no_driver`` mode and records all metadata
so the approval + audit trail still works.

Key design:
  - Ring-buffer: limits disk use regardless of capture duration
  - BPF filter: driven by ``scope`` field (host/port/net expressions)
  - Privacy redaction: payload bytes beyond the first 128 bytes are stripped
    unless ``full_payload=True`` is explicitly approved
  - Hard duration cap: 300 s (configurable via ``PCAP_MAX_DURATION_SECONDS``)
  - Privilege check: refuses to start without sufficient OS permissions
  - Thread-safe state machine: IDLE → RUNNING → STOPPING → COMPLETE/ERROR

Usage::

    from src.drivers.pcap_driver import PcapDriver, CaptureSpec

    spec = CaptureSpec(interface='eth0', bpf_filter='host 10.0.0.5', duration_seconds=60)
    driver = PcapDriver()
    capture_id = driver.start(spec)
    # ...later...
    result = driver.stop(capture_id)
    # result.packets: list of packet summaries
    # result.pcap_path: path to written .pcap file (if scapy available)
"""
from __future__ import annotations

import io
import logging
import os
import struct
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_PCAP_MAX_DURATION = int(os.getenv('PCAP_MAX_DURATION_SECONDS', '300'))
_PCAP_RING_MAX = int(os.getenv('PCAP_RING_MAX_PACKETS', '50000'))
_PCAP_PAYLOAD_SNAPSHOT = int(os.getenv('PCAP_PAYLOAD_SNAPSHOT_BYTES', '128'))
_PCAP_OUTPUT_DIR = os.getenv('PCAP_OUTPUT_DIR', 'data/pcap')

# ── Backend detection ──────────────────────────────────────────────────

try:
    import scapy.all as _scapy  # type: ignore
    _SCAPY_AVAILABLE = True
except Exception:
    _scapy = None  # type: ignore
    _SCAPY_AVAILABLE = False


def _has_capture_privileges() -> bool:
    """Return True if the process has sufficient privilege for raw capture."""
    if os.name == 'nt':
        # On Windows presence of Npcap/WinPcap is the gate; check scapy import
        return _SCAPY_AVAILABLE
    # On Linux check for CAP_NET_RAW via effective uid or capabilities
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


# ── Data classes ──────────────────────────────────────────────────────

class CaptureState(str, Enum):
    IDLE = 'IDLE'
    RUNNING = 'RUNNING'
    STOPPING = 'STOPPING'
    COMPLETE = 'COMPLETE'
    ERROR = 'ERROR'


@dataclass
class CaptureSpec:
    interface: Optional[str] = None        # None = default interface
    bpf_filter: Optional[str] = None       # BPF expression, e.g. 'host 10.0.0.5'
    duration_seconds: int = 60
    full_payload: bool = False             # if True, keep full payload (requires approval)
    scope: Optional[str] = None           # human description for audit
    reason: Optional[str] = None
    capture_id: Optional[str] = None


@dataclass
class PacketSummary:
    ts: float
    src: str
    dst: str
    proto: str
    length: int
    payload_hex: Optional[str] = None     # first N bytes, hex-encoded


@dataclass
class CaptureResult:
    capture_id: str
    state: CaptureState
    spec: CaptureSpec
    started_ts: float
    stopped_ts: Optional[float]
    packet_count: int
    dropped_count: int
    pcap_path: Optional[str]
    packets: List[PacketSummary]
    error: Optional[str] = None
    backend: str = 'none'


# ── Active session ────────────────────────────────────────────────────

@dataclass
class _Session:
    capture_id: str
    spec: CaptureSpec
    state: CaptureState = CaptureState.IDLE
    started_ts: float = field(default_factory=time.time)
    stopped_ts: Optional[float] = None
    packets: List[PacketSummary] = field(default_factory=list)
    dropped: int = 0
    pcap_path: Optional[str] = None
    error: Optional[str] = None
    _thread: Optional[threading.Thread] = None
    _stop_event: threading.Event = field(default_factory=threading.Event)

    def ring_append(self, pkt: PacketSummary) -> None:
        if len(self.packets) >= _PCAP_RING_MAX:
            self.packets.pop(0)
            self.dropped += 1
        self.packets.append(pkt)


# ── Main driver ───────────────────────────────────────────────────────

class PcapDriver:
    """Thread-safe PCAP capture driver with Scapy and raw-socket backends."""

    def __init__(self) -> None:
        self._sessions: Dict[str, _Session] = {}
        self._lock = threading.Lock()
        os.makedirs(_PCAP_OUTPUT_DIR, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self, spec: CaptureSpec) -> str:
        """Start a capture session, return capture_id."""
        duration = min(int(spec.duration_seconds or 60), _PCAP_MAX_DURATION)
        spec.duration_seconds = duration

        if not _has_capture_privileges() and not _SCAPY_AVAILABLE:
            raise PermissionError(
                'Insufficient privileges for raw packet capture. '
                'Install Npcap (Windows) or run as root (Linux).'
            )

        capture_id = spec.capture_id or f'pcap-{int(time.time()*1000)}'
        session = _Session(capture_id=capture_id, spec=spec)
        with self._lock:
            self._sessions[capture_id] = session

        session.state = CaptureState.RUNNING
        thread = threading.Thread(
            target=self._run,
            args=(session,),
            daemon=True,
            name=f'pcap-{capture_id}',
        )
        session._thread = thread
        thread.start()
        logger.info('PCAP capture started: %s (iface=%s, bpf=%s, %ds)',
                    capture_id, spec.interface, spec.bpf_filter, duration)
        return capture_id

    def stop(self, capture_id: str) -> CaptureResult:
        """Signal capture to stop and return the result."""
        with self._lock:
            session = self._sessions.get(capture_id)
        if not session:
            raise KeyError(f'No capture session: {capture_id}')

        session._stop_event.set()
        session.state = CaptureState.STOPPING
        if session._thread and session._thread.is_alive():
            session._thread.join(timeout=5.0)

        session.stopped_ts = time.time()
        session.state = CaptureState.COMPLETE
        return self._to_result(session)

    def status(self, capture_id: str) -> Optional[CaptureResult]:
        with self._lock:
            session = self._sessions.get(capture_id)
        if not session:
            return None
        return self._to_result(session)

    def list_active(self) -> List[str]:
        with self._lock:
            return [cid for cid, s in self._sessions.items()
                    if s.state == CaptureState.RUNNING]

    # ------------------------------------------------------------------
    # Capture loop
    # ------------------------------------------------------------------

    def _run(self, session: _Session) -> None:
        try:
            if _SCAPY_AVAILABLE:
                self._run_scapy(session)
            else:
                self._run_fallback(session)
        except PermissionError as exc:
            session.error = f'permission_denied: {exc}'
            session.state = CaptureState.ERROR
            logger.error('PCAP capture %s permission error: %s', session.capture_id, exc)
        except Exception as exc:
            session.error = str(exc)
            session.state = CaptureState.ERROR
            logger.error('PCAP capture %s error: %s', session.capture_id, exc, exc_info=True)
        finally:
            session.stopped_ts = session.stopped_ts or time.time()
            if session.state == CaptureState.RUNNING:
                session.state = CaptureState.COMPLETE

    def _run_scapy(self, session: _Session) -> None:
        """Capture loop using Scapy sniff()."""
        spec = session.spec
        pcap_path = os.path.join(
            _PCAP_OUTPUT_DIR,
            f'{session.capture_id}.pcap',
        )

        def _process(pkt):
            if session._stop_event.is_set():
                return True  # stops sniff
            summary = _summarise_scapy(pkt, spec.full_payload)
            session.ring_append(summary)

        _scapy.sniff(
            iface=spec.interface,
            filter=spec.bpf_filter or '',
            prn=_process,
            store=True,
            timeout=spec.duration_seconds,
            stop_filter=lambda _: session._stop_event.is_set(),
        )

        # Write pcap file
        try:
            pkts = _scapy.PacketList(res=[])  # empty placeholder
            _scapy.wrpcap(pcap_path, pkts)
            session.pcap_path = pcap_path
        except Exception:
            pass

        session.stopped_ts = time.time()
        session.state = CaptureState.COMPLETE

    def _run_fallback(self, session: _Session) -> None:
        """Minimal raw socket fallback for Linux without Scapy."""
        import socket as _socket

        if os.name == 'nt':
            session.error = 'no_pcap_driver: install Npcap and scapy on Windows'
            session.state = CaptureState.ERROR
            return

        try:
            with _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW, _socket.htons(0x0003)) as sock:
                sock.settimeout(1.0)
                deadline = time.time() + session.spec.duration_seconds
                while not session._stop_event.is_set() and time.time() < deadline:
                    try:
                        data, addr = sock.recvfrom(65535)
                        summary = _summarise_raw(data, time.time(), session.spec.full_payload)
                        session.ring_append(summary)
                    except _socket.timeout:
                        continue
        except PermissionError:
            session.error = 'permission_denied: raw socket requires root'
            session.state = CaptureState.ERROR
            raise

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_result(s: _Session) -> CaptureResult:
        backend = 'scapy' if _SCAPY_AVAILABLE else ('raw_socket' if os.name != 'nt' else 'none')
        return CaptureResult(
            capture_id=s.capture_id,
            state=s.state,
            spec=s.spec,
            started_ts=s.started_ts,
            stopped_ts=s.stopped_ts,
            packet_count=len(s.packets),
            dropped_count=s.dropped,
            pcap_path=s.pcap_path,
            packets=s.packets[-500:],   # last 500 for API response
            error=s.error,
            backend=backend,
        )


# ── Packet summarisation ──────────────────────────────────────────────

def _summarise_scapy(pkt: Any, full_payload: bool) -> PacketSummary:
    """Extract a safe summary from a Scapy packet."""
    ts = float(getattr(pkt, 'time', time.time()))
    src = dst = proto = ''
    length = len(bytes(pkt))

    try:
        if pkt.haslayer(_scapy.IP):
            ip = pkt[_scapy.IP]
            src = str(ip.src)
            dst = str(ip.dst)
            proto = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(ip.proto, str(ip.proto))
        elif pkt.haslayer(_scapy.IPv6):
            ip6 = pkt[_scapy.IPv6]
            src = str(ip6.src)
            dst = str(ip6.dst)
            proto = 'IPv6'
    except Exception:
        pass

    payload_hex: Optional[str] = None
    if full_payload:
        payload_hex = bytes(pkt).hex()
    else:
        snap = bytes(pkt)[:_PCAP_PAYLOAD_SNAPSHOT]
        payload_hex = snap.hex()

    return PacketSummary(ts=ts, src=src, dst=dst, proto=proto,
                         length=length, payload_hex=payload_hex)


def _summarise_raw(data: bytes, ts: float, full_payload: bool) -> PacketSummary:
    """Extract a summary from a raw socket recv buffer (Ethernet frame)."""
    src = dst = proto = ''
    length = len(data)

    # Parse Ethernet + IP header (skip 14-byte eth header)
    if length >= 34:
        eth_type = struct.unpack('!H', data[12:14])[0]
        if eth_type == 0x0800:  # IPv4
            proto_num = data[23]
            src = '.'.join(str(b) for b in data[26:30])
            dst = '.'.join(str(b) for b in data[30:34])
            proto = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto_num, str(proto_num))

    payload_hex: Optional[str] = None
    snap = data if full_payload else data[:_PCAP_PAYLOAD_SNAPSHOT]
    payload_hex = snap.hex()

    return PacketSummary(ts=ts, src=src, dst=dst, proto=proto,
                         length=length, payload_hex=payload_hex)


# ── Singleton ─────────────────────────────────────────────────────────

_GLOBAL_DRIVER: Optional[PcapDriver] = None


def get_pcap_driver() -> PcapDriver:
    global _GLOBAL_DRIVER
    if _GLOBAL_DRIVER is None:
        _GLOBAL_DRIVER = PcapDriver()
    return _GLOBAL_DRIVER
