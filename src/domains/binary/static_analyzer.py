import os
import math
from typing import Dict, Any

try:
    import pefile  # type: ignore
except Exception:
    pefile = None
try:
    from elftools.elf.elffile import ELFFile  # type: ignore
except Exception:
    ELFFile = None


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = len(data)
    for c in counts:
        if c == 0:
            continue
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


def analyze_path(path: str) -> Dict[str, Any]:
    """Lightweight static analysis: detect type (PE/ELF), entropy, signature presence.
    Returns a dict with keys: kind, entropy, signed, sections, size.
    """
    result: Dict[str, Any] = {
        'kind': 'unknown',
        'entropy': None,
        'signed': False,
        'sections': [],
        'size': None,
    }
    try:
        if not os.path.exists(path):
            return {**result, 'error': 'not_found'}
        result['size'] = os.path.getsize(path)
        with open(path, 'rb') as f:
            head = f.read(8)
            f.seek(0)
            data = f.read()
        result['entropy'] = _shannon_entropy(data[: min(len(data), 256 * 1024)])
        # PE detection
        if head[:2] == b'MZ' and pefile is not None:
            result['kind'] = 'pe'
            try:
                pe = pefile.PE(path)
                # Signed if security directory exists and size > 0
                try:
                    dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
                    result['signed'] = bool(getattr(dir_entry, 'Size', 0) or 0) > 0
                except Exception:
                    result['signed'] = False
                # Sections summary
                try:
                    result['sections'] = [
                        {'name': str(s.Name).strip("b'\x00"), 'size': int(s.SizeOfRawData)}
                        for s in pe.sections
                    ]
                except Exception:
                    pass
            except Exception:
                result['error'] = 'pe_parse_failed'
        # ELF detection
        elif head[:4] == b'\x7fELF' and ELFFile is not None:
            result['kind'] = 'elf'
            try:
                with open(path, 'rb') as f:
                    elf = ELFFile(f)
                    try:
                        result['sections'] = [
                            {'name': sec.name, 'size': sec['sh_size']}
                            for sec in elf.iter_sections()
                        ]
                    except Exception:
                        pass
                    # No standard signature field; leave signed False
                    result['signed'] = False
            except Exception:
                result['error'] = 'elf_parse_failed'
        else:
            result['kind'] = 'unknown'
    except Exception as exc:
        result['error'] = f'exception:{exc}'
    return result
