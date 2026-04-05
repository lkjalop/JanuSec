from typing import Optional, Dict
import re
from datetime import datetime


def is_cef(line: str) -> bool:
    return line.startswith("CEF:")


def parse_cef(line: str) -> Dict:
    # very small parser: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    parts = line.split("|", 7)
    if len(parts) < 7:
        return {}
    # extract extension key=val pairs
    ext = {}
    if len(parts) >= 8:
        ext_text = parts[7]
        for kv in re.findall(r"(\w+)=([^=]+?)(?=\s\w+=|$)", ext_text):
            k, v = kv
            v = v.strip()
            # try numeric conversion
            if re.fullmatch(r"\d+", v):
                v = int(v)
            else:
                try:
                    v = float(v)
                except Exception:
                    pass
            ext[k] = v
    # attempt to map common extension keys to canonical fields
    canonical = {}
    if ext:
        # common mappings
        if "src" in ext:
            canonical["src_ip"] = ext.get("src")
        if "dst" in ext:
            canonical["dst_ip"] = ext.get("dst")
        if "spt" in ext or "sourcePort" in ext:
            canonical["src_port"] = ext.get("spt") or ext.get("sourcePort")
        if "dpt" in ext or "destinationPort" in ext:
            canonical["dst_port"] = ext.get("dpt") or ext.get("destinationPort")
        if "rt" in ext or "rt1" in ext:
            # try parse as timestamp
            for k in ("rt", "rt1"):
                if k in ext:
                    try:
                        canonical["ts"] = datetime.fromtimestamp(int(ext[k]))
                    except Exception:
                        pass

    return {
        "vendor": parts[1],
        "product": parts[2],
        "version": parts[3],
        "name": parts[6] if len(parts) > 6 else None,
        "extension": ext,
        "canonical": canonical,
    }


def is_leef(line: str) -> bool:
    return line.startswith("LEEF:")


def parse_leef(line: str) -> Dict:
    # simplistic
    try:
        header, rest = line.split("\t", 1)
        parts = header.split(":")
        vendor = parts[1] if len(parts) > 1 else None
        ext = {}
        for kv in re.findall(r"(\w+)=([^\t]+)(?=\t|$)", rest):
            k, v = kv
            v = v.strip()
            if v.isdigit():
                v = int(v)
            ext[k] = v
        # map some LEEF keys to canonical fields
        canonical = {}
        if "src" in ext:
            canonical["src_ip"] = ext.get("src")
        if "dst" in ext:
            canonical["dst_ip"] = ext.get("dst")
        return {"vendor": vendor, "extension": ext, "canonical": canonical}
    except Exception:
        return {}
