#!/usr/bin/env python
"""Tiny CLI wrapper to view and toggle runtime feature flags.

Usage examples:
  python scripts/flags_cli.py list
  python scripts/flags_cli.py get FEATURE_SLO_ENFORCE_DISPLAY
  python scripts/flags_cli.py set FEATURE_SLO_ENFORCE_DISPLAY true
  python scripts/flags_cli.py clear FEATURE_SLO_ENFORCE_DISPLAY

By default, changes persist to config/flags.json (override with FLAGS_FILE env).
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from src.core.flags import (
    flags_snapshot,
    list_overrides,
    get_flag,
    set_flag,
    clear_flag,
)


def _to_bool(s: str) -> Any:
    low = s.lower()
    if low in {"true", "1", "yes", "y"}: return True
    if low in {"false", "0", "no", "n"}: return False
    try:
        # allow numbers as well
        if "." in s:
            return float(s)
        return int(s)
    except Exception:
        return s


def cmd_list(_: argparse.Namespace) -> int:
    eff = flags_snapshot()
    ov = list_overrides()
    print(json.dumps({"effective": eff, "overrides": ov}, indent=2))
    return 0


def cmd_get(ns: argparse.Namespace) -> int:
    val = get_flag(ns.name)
    print(json.dumps({"name": ns.name, "value": val}, indent=2))
    return 0


def cmd_set(ns: argparse.Namespace) -> int:
    val = _to_bool(ns.value)
    set_flag(ns.name, val, persist=not ns.no_persist)
    print(json.dumps({"name": ns.name, "value": get_flag(ns.name)}, indent=2))
    return 0


def cmd_clear(ns: argparse.Namespace) -> int:
    clear_flag(ns.name, persist=not ns.no_persist)
    print(json.dumps({"name": ns.name, "value": get_flag(ns.name)}, indent=2))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="JanuSec Flags CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    s_list = sub.add_parser("list", help="List effective flags and overrides")
    s_list.set_defaults(func=cmd_list)

    s_get = sub.add_parser("get", help="Get a flag value")
    s_get.add_argument("name")
    s_get.set_defaults(func=cmd_get)

    s_set = sub.add_parser("set", help="Set/override a flag (persist by default)")
    s_set.add_argument("name")
    s_set.add_argument("value")
    s_set.add_argument("--no-persist", action="store_true", help="Do not persist changes to flags.json")
    s_set.set_defaults(func=cmd_set)

    s_clear = sub.add_parser("clear", help="Clear a runtime override (persist by default)")
    s_clear.add_argument("name")
    s_clear.add_argument("--no-persist", action="store_true", help="Do not persist changes to flags.json")
    s_clear.set_defaults(func=cmd_clear)

    ns = p.parse_args(argv)
    return ns.func(ns)


if __name__ == "__main__":
    raise SystemExit(main())
