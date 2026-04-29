"""Postmortem section builders.

Each section module exposes one function ``build_s{N}_{name}(...)`` that
takes the same kwargs and returns a dict with at minimum:
    {
        "title": str,
        "auto_output": dict | None   # None for v2 stubs
    }

The assembler adds section_id, v1_status, overrides, signoff fields.
"""
