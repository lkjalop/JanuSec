"""Email attachment analysis helpers.

This is a lightweight analyzer that detects macros, mismatched extensions,
and high compression ratio archive bombs. It's intentionally small and
testable; extend with VirusTotal/MIME parsing in a follow-up.
"""
from typing import Dict, Any
import zipfile
import io


def analyze_attachment(content: bytes, filename: str) -> Dict[str, Any]:
    """Analyze a single attachment.

    Returns a dict with keys: `filename`, `size`, `is_macro`, `extension_mismatch`, `compression_ratio_estimate`, `suspicious`.
    """
    out: Dict[str, Any] = {'filename': filename, 'size': len(content)}
    lower = filename.lower()
    ext = lower.split('.')[-1] if '.' in lower else ''

    # Heuristic: Office macros often in .docm, .xlsm, or inside zip/office containers
    is_macro = False
    try:
        if ext in ('docm', 'xlsm', 'pptm'):
            is_macro = True
        # quick check: look for typical macro binary signature 'vbaProject.bin'
        if b'vbaProject.bin' in content:
            is_macro = True
    except Exception:
        is_macro = False

    # Extension mismatch heuristic: e.g., .jpg but content starts with PK (zip) or MZ
    extension_mismatch = False
    try:
        if ext in ('jpg','png','gif') and content[:4] in (b'PK\x03\x04', b'MZ\x90'):
            extension_mismatch = True
    except Exception:
        extension_mismatch = False

    # Archive compression ratio heuristic for basic zip bombs
    compression_ratio_estimate = None
    try:
        if content[:2] == b'PK':
            with io.BytesIO(content) as bio:
                try:
                    z = zipfile.ZipFile(bio)
                    total_uncompressed = sum((zi.file_size for zi in z.infolist()))
                    total_compressed = sum((zi.compress_size for zi in z.infolist())) or 1
                    compression_ratio_estimate = total_uncompressed / max(1, total_compressed)
                except Exception:
                    compression_ratio_estimate = None
    except Exception:
        compression_ratio_estimate = None

    suspicious = bool(is_macro) or bool(extension_mismatch) or (compression_ratio_estimate is not None and compression_ratio_estimate > 100)

    out.update({'is_macro': is_macro, 'extension_mismatch': extension_mismatch, 'compression_ratio_estimate': compression_ratio_estimate, 'suspicious': suspicious})
    return out


__all__ = ['analyze_attachment']
