"""Reject ambiguous storage identifiers; contain paths under their trusted root."""
import os
import re
from pathlib import Path


def storage_id(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", value):
        raise ValueError("Invalid storage identifier")
    if ".." in value or value.endswith(".") or value.split(".", 1)[0].upper() in {
        "CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))
    }:
        raise ValueError("Invalid storage identifier")
    return value


def storage_path(root, filename: str) -> str:
    storage_id(filename)
    base = os.path.realpath(root)
    candidate = os.path.realpath(os.path.join(base, filename))
    if os.path.commonpath([base, candidate]) != base:
        raise ValueError("Storage path escapes configured directory")
    return candidate
