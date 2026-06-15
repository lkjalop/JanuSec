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
    # CEF header: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Ext
    # parts[5] = Name, parts[6] = Severity (previously mis-indexed as name=parts[6]).
    name = parts[5] if len(parts) > 5 else None
    severity_raw = parts[6] if len(parts) > 6 else None

    # Map standard CEF extension keys -> Janusec canonical fields. Firewall/IPS logs
    # (FortiGate/Palo/Check Point in CEF) carry the threat-prevention signal in
    # act/cat/suser, which the old mapping dropped -> weak network attribution.
    canonical: Dict = {}
    if ext:
        if "src" in ext:
            canonical["src_ip"] = ext.get("src")
        if "dst" in ext:
            canonical["dst_ip"] = ext.get("dst")
        if "spt" in ext or "sourcePort" in ext:
            canonical["src_port"] = ext.get("spt") or ext.get("sourcePort")
        if "dpt" in ext or "destinationPort" in ext:
            canonical["dst_port"] = ext.get("dpt") or ext.get("destinationPort")
        _user = ext.get("suser") or ext.get("sourceUserName") or ext.get("duser")
        if _user:
            canonical["user"] = _user
        _act = ext.get("act") or ext.get("deviceAction")
        if _act:
            canonical["action"] = _act
        _cat = ext.get("cat") or ext.get("cs1") or ext.get("categoryBehavior")
        if _cat:
            canonical["category"] = _cat
        if ext.get("cn1") or ext.get("dhost"):
            canonical["hostname"] = ext.get("dhost") or ext.get("cn1")
        for k in ("rt", "rt1", "end", "start"):
            if k in ext:
                try:
                    canonical["timestamp"] = datetime.fromtimestamp(int(ext[k]) / 1000.0).isoformat()
                except Exception:
                    pass
                break

    # Severity: CEF is 0-10 (or Low/Medium/High/Very-High) -> janusec band.
    sev = None
    if severity_raw is not None:
        s = str(severity_raw).strip().lower()
        if s.isdigit():
            n = int(s)
            sev = 'critical' if n >= 9 else 'high' if n >= 7 else 'medium' if n >= 4 else 'low'
        else:
            sev = {'very-high': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low'}.get(s)
    if sev:
        canonical["severity"] = sev
    if name:
        canonical["event_name"] = name
        canonical["event_signature"] = name

    # Flat output: canonical fields at top level (normalize_row-ready) PLUS the
    # legacy keys (name/extension/vendor/...) that syslog_collector relies on.
    out: Dict = dict(canonical)
    out.update({
        "vendor": parts[1],
        "product": parts[2],
        "version": parts[3],
        "name": name,
        "severity_raw": severity_raw,
        "extension": ext,
        "canonical": canonical,
        "_source": f"{parts[1]} {parts[2]}".strip().lower(),  # e.g. 'fortinet fortigate' -> NETWORK
    })
    return out


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
