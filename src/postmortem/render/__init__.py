"""Postmortem rendering layer.

Three renderers, all stateless. Each takes a PostmortemDocument and returns
output for a different consumer:

  - html_renderer.render_postmortem_html(doc) -> str (HTML fragment for the tab)
  - pdf_renderer.render_postmortem_pdf(doc, out_path) -> str (writes PDF, returns path)
  - one_pager_renderer.render_compliance_one_pager(doc, out_path) -> str
"""
from __future__ import annotations

from .html_renderer import render_postmortem_html
from .pdf_renderer import render_postmortem_pdf
from .one_pager_renderer import render_compliance_one_pager

__all__ = [
    "render_postmortem_html",
    "render_postmortem_pdf",
    "render_compliance_one_pager",
]
