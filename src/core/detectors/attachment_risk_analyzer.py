"""AttachmentRiskAnalyzer — production-grade attachment threat signal extractor.

Extends the basic attachment_analyzer.py with byte-level analysis:
    email:attachment_double_ext     — Double extension hiding (e.g. invoice.pdf.exe)
    email:attachment_zip_bomb       — Compression ratio exceeds bomb threshold
    email:attachment_ole_macro      — OLE Compound Document with embedded macro (byte-sig)
    email:attachment_rtf_exploit    — RTF with object embedding patterns
    email:attachment_html_smuggling — HTML smuggling: base64 blob in <a> or <script>
    email:attachment_polyglot       — File passes as two formats simultaneously (magic mismatch)
    email:attachment_lnk_target     — LNK shortcut pointing to suspicious target

All factors include sha256, filename, score, reason, and MITRE/STRIDE tags.
HopGraph wiring: add edge (hash:<sha256>, domain:<sender_domain>, 'attachment_risk', weight=score)
"""
from __future__ import annotations

import base64
import hashlib
import io
import math
import re
import struct
import zipfile
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Magic byte signatures
# ---------------------------------------------------------------------------

# OLE Compound Document (Word/Excel/older Office with macros)
_OLE_MAGIC         = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
# ZIP (modern .docx/.xlsx — but these only have macros if the _macro stream exists)
_ZIP_MAGIC         = b'PK\x03\x04'
# RTF
_RTF_MAGIC         = b'{\\rtf'
# PDF
_PDF_MAGIC         = b'%PDF'
# Windows executable (MZ)
_MZ_MAGIC          = b'MZ'
# Windows LNK shortcut
_LNK_MAGIC         = b'\x4c\x00\x00\x00\x01\x14\x02\x00'
# 7z
_SEVENZ_MAGIC      = b'7z\xbc\xaf\x27\x1c'
# RAR
_RAR_MAGIC         = b'Rar!'

# Zip bomb thresholds
_ZIP_BOMB_RATIO      = 100.0  # decompressed / compressed > 100x
_ZIP_BOMB_MAX_NESTED = 3      # nested zip layers before flagging

# OLE streams that indicate VBA macro presence
_OLE_MACRO_STREAM_NAMES = {b'vba', b'VBA', b'macros', b'Macros', b'_VBA_PROJECT'}

# Double-extension detection — the dangerous extension MUST be last
_EXEC_EXTENSIONS = {
    '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js',
    '.jar', '.hta', '.msi', '.com', '.pif', '.lnk', '.wsf', '.wsh',
    '.msp', '.mst', '.cpl', '.inf', '.reg', '.msc', '.url',
}
# Benign-looking extensions that can precede the dangerous extension
_COVER_EXTENSIONS = {
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.txt', '.csv', '.zip', '.rar', '.7z', '.jpg', '.jpeg',
    '.png', '.gif', '.bmp', '.tiff', '.mp4', '.mov', '.avi',
}

# HTML smuggling patterns
_HTML_BLOB_PATTERN = re.compile(
    rb'(?:atob|fromCharCode|unescape)\s*\(',
    re.IGNORECASE,
)
_HTML_BLOB_BASE64  = re.compile(
    rb'(?:data:application/(?:octet-stream|x-executable);base64,)[A-Za-z0-9+/=]{200,}',
    re.IGNORECASE,
)

# RTF object embedding
_RTF_OBJDATA = re.compile(rb'\\objdata\s+[0-9a-fA-F]{16,}', re.IGNORECASE)
_RTF_EQUATION = re.compile(rb'\\object\\objemb', re.IGNORECASE)  # CVE-2017-11882 pattern

# LNK target path extract
_LNK_CMD_PATTERN = re.compile(
    rb'(?:cmd\.exe|powershell|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> str:
    try:
        return hashlib.sha256(data).hexdigest()
    except Exception:
        return ''


def _shannon_entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = float(len(data))
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _to_bytes(content: Any) -> bytes:
    if content is None:
        return b''
    if isinstance(content, (bytes, bytearray)):
        return bytes(content)
    if isinstance(content, str):
        try:
            return base64.b64decode(content + '==', validate=False)
        except Exception:
            return content.encode('utf-8', errors='ignore')
    return b''


def _detect_double_extension(filename: str) -> Optional[Tuple[str, str]]:
    """Return (cover_ext, exec_ext) if double extension detected, else None."""
    name = filename.lower().strip()
    # Walk backwards through the filename looking for two extensions
    parts = name.rsplit('.', 2)
    if len(parts) < 3:
        return None
    ext2 = '.' + parts[-1]
    ext1 = '.' + parts[-2]
    if ext2 in _EXEC_EXTENSIONS and ext1 in _COVER_EXTENSIONS:
        return (ext1, ext2)
    return None


def _check_zip_bomb(data: bytes, nested_depth: int = 0) -> Tuple[bool, float, int]:
    """Check if ZIP data is a zip bomb. Returns (is_bomb, ratio, nested_depth)."""
    if nested_depth > _ZIP_BOMB_MAX_NESTED:
        return True, float('inf'), nested_depth
    try:
        buf = io.BytesIO(data)
        with zipfile.ZipFile(buf) as zf:
            total_compressed   = sum(i.compress_size for i in zf.infolist())
            total_uncompressed = sum(i.file_size for i in zf.infolist())
            if total_compressed == 0:
                return False, 0.0, nested_depth
            ratio = total_uncompressed / total_compressed
            if ratio >= _ZIP_BOMB_RATIO:
                return True, ratio, nested_depth
            # Check nested ZIPs (one level deep only to avoid recursion DOS)
            if nested_depth < _ZIP_BOMB_MAX_NESTED:
                for item in zf.infolist():
                    if item.filename.lower().endswith('.zip'):
                        try:
                            inner = zf.read(item.filename)
                            is_bomb, inner_ratio, depth = _check_zip_bomb(inner, nested_depth + 1)
                            if is_bomb:
                                return True, inner_ratio, depth
                        except Exception:
                            continue
        return False, ratio, nested_depth
    except Exception:
        return False, 0.0, nested_depth


def _check_ole_macro(data: bytes) -> bool:
    """Return True if the OLE document likely contains a VBA macro stream."""
    if not data.startswith(_OLE_MAGIC):
        return False
    # Scan for known macro stream name bytes in the compound document
    for stream in _OLE_MACRO_STREAM_NAMES:
        if stream in data:
            return True
    # Backup: look for VBA p-code signatures
    if b'Attribute VB_' in data or b'vbaProject' in data:
        return True
    return False


def _check_ooxml_macro(data: bytes, filename: str) -> bool:
    """Check Open XML (.docm/.xlsm) for embedded vbaProject.bin."""
    if not data.startswith(_ZIP_MAGIC):
        return False
    try:
        buf = io.BytesIO(data)
        with zipfile.ZipFile(buf) as zf:
            names_lower = [n.lower() for n in zf.namelist()]
            # vbaProject.bin is the definitive indicator
            if any('vbaproject.bin' in n for n in names_lower):
                return True
            # Fallback: any stream ending in .bin inside xl/ or word/ subdirs
            if any(n.endswith('.bin') and ('xl/' in n or 'word/' in n) for n in names_lower):
                return True
    except Exception:
        pass
    return False


def _check_rtf_exploit(data: bytes) -> bool:
    """Detect RTF with object embedding (CVE-2017-11882 style)."""
    if not data.lstrip(b'\r\n ').startswith(_RTF_MAGIC):
        return False
    return bool(_RTF_OBJDATA.search(data)) or bool(_RTF_EQUATION.search(data))


def _check_html_smuggling(data: bytes) -> bool:
    """Detect HTML attachment used as a smuggling container."""
    if not (b'<html' in data[:2048].lower() or b'<!doctype html' in data[:2048].lower()):
        return False
    return bool(_HTML_BLOB_PATTERN.search(data)) or bool(_HTML_BLOB_BASE64.search(data))


def _check_polyglot(data: bytes, filename: str) -> Optional[str]:
    """Detect polyglot files (pass as two formats simultaneously).
    Returns description string if detected, else None.
    """
    ext = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''
    # File claims to be PDF but starts with ZIP
    if ext == 'pdf' and data.startswith(_ZIP_MAGIC):
        return 'Claimed PDF but has ZIP magic bytes (PDF+ZIP polyglot)'
    # File claims to be image but has MZ magic
    if ext in {'jpg', 'jpeg', 'png', 'gif', 'bmp'} and data.startswith(_MZ_MAGIC):
        return 'Claimed image but has MZ (PE) magic bytes (image+PE polyglot)'
    # File claims to be ZIP but starts with PDF
    if ext == 'zip' and data.startswith(_PDF_MAGIC):
        return 'Claimed ZIP but has PDF magic bytes (PDF+ZIP polyglot)'
    return None


def _check_lnk_target(data: bytes) -> Optional[str]:
    """Detect Windows LNK shortcuts pointing to suspicious targets."""
    if not data.startswith(_LNK_MAGIC):
        return None
    match = _LNK_CMD_PATTERN.search(data)
    if match:
        # Extract a context window around the match
        start = max(0, match.start() - 20)
        end = min(len(data), match.end() + 80)
        try:
            snippet = data[start:end].decode('utf-16-le', errors='ignore').replace('\x00', '').strip()
            if not snippet:
                snippet = data[start:end].decode('utf-8', errors='ignore').strip()
        except Exception:
            snippet = '(undecodable)'
        return snippet[:200]
    return None


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

def analyze_attachment_risk(
    filename: str,
    content: Any,
    mime: str = '',
    sender_domain: str = '',
    event_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Analyze a single attachment and return a list of risk factor dicts.

    Args:
        filename:      Original attachment filename.
        content:       Raw bytes, bytearray, or base64-encoded string.
        mime:          MIME type string.
        sender_domain: Originating sender domain (for HopGraph edge metadata).
        event_id:      Optional event ID for dedup.

    Returns:
        List of factor dicts matching the existing detector pattern.
    """
    factors: List[Dict[str, Any]] = []
    data = _to_bytes(content)
    sha  = _sha256(data)

    base_meta = {
        'filename': filename,
        'sha256': sha,
        'mime': mime,
        'sender_domain': sender_domain,
    }

    # ------------------------------------------------------------------
    # 1. Double extension
    # ------------------------------------------------------------------
    dext = _detect_double_extension(filename)
    if dext:
        cover_ext, exec_ext = dext
        factors.append({
            'factor': 'email:attachment_double_ext',
            'score': 0.82,
            'reason': f'Double extension detected: "{cover_ext}" cover + "{exec_ext}" exec (e.g., invoice.pdf.exe)',
            'cover_ext': cover_ext,
            'exec_ext': exec_ext,
            'tags': ['ATTACK:T1566.001', 'ATTACK:T1036.007', 'STRIDE:tampering'],
            **base_meta,
        })

    if not data:
        return factors  # no bytes — can't do further analysis

    # ------------------------------------------------------------------
    # 2. Zip bomb
    # ------------------------------------------------------------------
    ext_lower = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''
    if data.startswith(_ZIP_MAGIC) or ext_lower in {'zip', 'docx', 'xlsx', 'pptx', 'jar', 'apk'}:
        is_bomb, ratio, depth = _check_zip_bomb(data)
        if is_bomb:
            factors.append({
                'factor': 'email:attachment_zip_bomb',
                'score': 0.88,
                'reason': f'Zip bomb detected: compression ratio {ratio:.0f}x at nesting depth {depth}',
                'compression_ratio': round(ratio, 1) if ratio != float('inf') else 'inf',
                'nested_depth': depth,
                'tags': ['ATTACK:T1566.001', 'ATTACK:T1499', 'STRIDE:denial'],
                **base_meta,
            })

    # ------------------------------------------------------------------
    # 3. OLE / OOXML macro
    # ------------------------------------------------------------------
    has_ole_macro = _check_ole_macro(data)
    if not has_ole_macro:
        has_ole_macro = _check_ooxml_macro(data, filename)

    if has_ole_macro:
        # Score slightly higher if it also has suspicious filename
        fn_lower = filename.lower()
        suspicious_name = any(
            tok in fn_lower for tok in ('invoice', 'payment', 'urgent', 'unlock', 'resume', 'order')
        )
        factors.append({
            'factor': 'email:attachment_ole_macro',
            'score': 0.85 if suspicious_name else 0.75,
            'reason': 'OLE Compound Document or OOXML file contains embedded VBA macro stream (vbaProject.bin or Attribute VB_)',
            'suspicious_filename': suspicious_name,
            'tags': ['ATTACK:T1566.001', 'ATTACK:T1204.002', 'ATTACK:T1059.005', 'STRIDE:tampering'],
            **base_meta,
        })

    # ------------------------------------------------------------------
    # 4. RTF exploit pattern
    # ------------------------------------------------------------------
    if _check_rtf_exploit(data):
        factors.append({
            'factor': 'email:attachment_rtf_exploit',
            'score': 0.87,
            'reason': 'RTF attachment contains \\objdata or \\objemb pattern consistent with CVE-2017-11882 / OLE exploit',
            'tags': ['ATTACK:T1566.001', 'ATTACK:T1203', 'ATTACK:T1204.002', 'STRIDE:tampering'],
            **base_meta,
        })

    # ------------------------------------------------------------------
    # 5. HTML smuggling
    # ------------------------------------------------------------------
    if _check_html_smuggling(data):
        factors.append({
            'factor': 'email:attachment_html_smuggling',
            'score': 0.80,
            'reason': 'HTML attachment contains embedded base64 blob or dynamic decoding (atob / fromCharCode / unescape) consistent with HTML smuggling',
            'tags': ['ATTACK:T1566.001', 'ATTACK:T1027.006', 'STRIDE:tampering'],
            **base_meta,
        })

    # ------------------------------------------------------------------
    # 6. Polyglot detection
    # ------------------------------------------------------------------
    poly_desc = _check_polyglot(data, filename)
    if poly_desc:
        factors.append({
            'factor': 'email:attachment_polyglot',
            'score': 0.78,
            'reason': poly_desc,
            'tags': ['ATTACK:T1566.001', 'ATTACK:T1036', 'STRIDE:tampering'],
            **base_meta,
        })

    # ------------------------------------------------------------------
    # 7. LNK shortcut with suspicious target
    # ------------------------------------------------------------------
    lnk_target = _check_lnk_target(data)
    if lnk_target:
        factors.append({
            'factor': 'email:attachment_lnk_target',
            'score': 0.83,
            'reason': f'LNK shortcut targets suspicious executable: "{lnk_target}"',
            'lnk_target_snippet': lnk_target,
            'tags': ['ATTACK:T1566.001', 'ATTACK:T1547.009', 'ATTACK:T1059', 'STRIDE:tampering'],
            **base_meta,
        })

    return factors


def analyze_attachments_risk(runtime, event_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Runtime adapter — mirrors the interface of the existing attachment_analyzer.analyze_attachments.

    Processes runtime.email_messages and returns combined factor list.
    """
    factors: List[Dict[str, Any]] = []
    msgs = getattr(runtime, 'email_messages', []) or []

    for m in msgs:
        try:
            fn      = str(m.get('filename') or '')
            content = m.get('content')
            mime    = str(m.get('mime') or '')
            sender  = str(m.get('sender_domain') or m.get('from_domain') or '')
            if not fn:
                continue
            factors.extend(
                analyze_attachment_risk(fn, content, mime=mime, sender_domain=sender, event_id=event_id)
            )
        except Exception:
            continue

    return factors


__all__ = ['analyze_attachment_risk', 'analyze_attachments_risk']
