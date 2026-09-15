"""JanuSec Postmortem Assembler module.

Public API:
    from src.postmortem.postmortem_assembler import (
        assemble, get_computed_section, all_sections_signed, signoff_summary,
    )
    from src.postmortem.human_edits import append_override
"""
from __future__ import annotations

from .postmortem_assembler import (
    assemble,
    get_computed_section,
    all_sections_signed,
    signoff_summary,
    POSTMORTEM_VERSION,
)
from .human_edits import append_override

__all__ = [
    "assemble",
    "get_computed_section",
    "all_sections_signed",
    "signoff_summary",
    "POSTMORTEM_VERSION",
    "append_override",
]
