"""Lightweight local attachment OCR/visual analysis helpers.

This module intentionally stays evidence-first: it extracts bounded local text
and emits flags/leads for analysts. It does not make autonomous visual
classification decisions or persist raw provider reasoning.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


_PAYMENT_TERMS = re.compile(
    r"\b(wire transfer|bank details|remittance|invoice|payment|supplier|account changed|ach|iban|swift)\b",
    re.IGNORECASE,
)
_EXECUTIVE_TERMS = re.compile(r"\b(ceo|cfo|executive|approval|urgent)\b", re.IGNORECASE)


def _extract_pdf_text(path: Path) -> tuple[str, list[str]]:
    methods: list[str] = []
    text = ""
    try:
        from pypdf import PdfReader  # type: ignore

        reader = PdfReader(str(path))
        chunks = []
        for page in reader.pages[:5]:
            try:
                chunks.append(page.extract_text() or "")
            except Exception:
                continue
        text = "\n".join(chunk for chunk in chunks if chunk).strip()
        if text:
            methods.append("pypdf")
    except Exception:
        text = ""
    if text:
        return text, methods
    try:
        from pdfminer.high_level import extract_text  # type: ignore

        text = (extract_text(str(path), maxpages=5) or "").strip()
        if text:
            methods.append("pdfminer")
    except Exception:
        text = ""
    return text, methods


def analyze_attachment_visual(attachment: dict[str, Any] | None) -> dict[str, Any]:
    """Extract local OCR/visual evidence for an attachment-like payload.

    Returns a stable, metadata-only result suitable for assessment rows and
    persona reports. Extraction failures degrade to explicit analyst leads.
    """
    attachment = attachment or {}
    name = str(attachment.get("attachment_name") or attachment.get("filename") or "")
    path_value = attachment.get("attachment_path") or attachment.get("path")
    path = Path(str(path_value)) if path_value else None
    suffix = (path.suffix if path else Path(name).suffix).lower()
    extracted_text = ""
    methods: list[str] = []
    errors: list[str] = []
    if path and path.exists() and suffix == ".pdf":
        extracted_text, methods = _extract_pdf_text(path)
        if not extracted_text:
            errors.append("pdf_text_unavailable")
    elif suffix in {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"}:
        methods.append("image_metadata")
    elif suffix:
        methods.append("metadata")

    haystack = f"{name}\n{extracted_text}"
    visual_flags: list[str] = []
    confirmation_leads: list[dict[str, Any]] = []
    denial_leads: list[dict[str, Any]] = []
    missing_telemetry: list[str] = []

    if _PAYMENT_TERMS.search(haystack):
        visual_flags.append("payment_lure")
        confirmation_leads.append({
            "lead": "Validate payment-change language against approved supplier and finance workflows.",
            "why_it_matters": "Payment lures require business-process corroboration before closure.",
            "expected_information_gain": 0.72,
        })
    if _EXECUTIVE_TERMS.search(haystack):
        visual_flags.append("executive_targeting")
        confirmation_leads.append({
            "lead": "Confirm whether the executive recipient opened the attachment or submitted credentials/payment approval.",
            "why_it_matters": "Executive targeting changes containment and business-review priority.",
            "expected_information_gain": 0.68,
        })
    if "qr" in haystack.lower():
        visual_flags.append("qr_lure_candidate")
        missing_telemetry.append("qr_destination_resolution")
        confirmation_leads.append({
            "lead": "Decode the QR destination and compare it with DNS, proxy, browser, and mobile-device telemetry.",
            "why_it_matters": "QR attacks move the evidence path outside normal email-click telemetry.",
            "expected_information_gain": 0.78,
        })

    if not methods or suffix in {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"}:
        missing_telemetry.extend(["ocr_attachment_review", "visual_brand_baseline"])
        denial_leads.append({
            "lead": "Compare attachment branding and layout against a trusted supplier baseline before confirming impersonation.",
            "why_it_matters": "Brand drift can confirm a lure, while a verified baseline can de-escalate the hypothesis.",
            "expected_information_gain": 0.61,
        })

    return {
        "enabled": True,
        "attachment_name": name,
        "attachment_path": str(path) if path else None,
        "extraction_methods": methods,
        "extracted_text": extracted_text,
        "qr_targets": [],
        "visual_flags": sorted(set(visual_flags)),
        "steganography_suspicion": False,
        "confidence": 0.7 if extracted_text else 0.35,
        "source_provenance": {
            "source": "local_attachment_vision",
            "method": methods[0] if methods else "lead_only",
        },
        "confirmation_leads": confirmation_leads,
        "denial_leads": denial_leads,
        "high_value_missing_telemetry": sorted(set(missing_telemetry)),
        "errors": errors,
    }
