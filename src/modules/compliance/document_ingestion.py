"""Lightweight document ingestion for compliance evidence.

- Supports PDF (via pypdf) and plain text files.
- Normalizes whitespace and chunks into overlapping blocks for scoring.

Output chunk schema:
  {
    'id': <uuid>,
    'source_file': <str>,
    'chunk_index': <int>,
    'text': <str>,
    'char_len': <int>,
  }
"""
from __future__ import annotations

from typing import List, Dict, Iterable
from pathlib import Path
import uuid
import re


def _load_pdf_text_bytes(data: bytes) -> str:
    try:
        from pypdf import PdfReader  # type: ignore
    except Exception:
        return "[ERROR] pypdf not installed; cannot parse PDF"
    try:
        import io
        reader = PdfReader(io.BytesIO(data))
        parts: List[str] = []
        for page in reader.pages:
            try:
                parts.append(page.extract_text() or "")
            except Exception:
                parts.append("")
        return "\n".join(parts)
    except Exception as e:
        return f"[PDF_READ_ERROR] {e}"


def _load_text_bytes(data: bytes) -> str:
    try:
        return data.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"[TEXT_READ_ERROR] {e}"


def normalize_text(raw: str) -> str:
    cleaned = re.sub(r"\s+", " ", raw).strip()
    return cleaned


def chunk_text(text: str, max_chars: int = 1200, overlap: int = 120) -> List[str]:
    chunks: List[str] = []
    start = 0
    n = len(text)
    while start < n:
        end = min(start + max_chars, n)
        chunk = text[start:end]
        chunks.append(chunk)
        if end == n:
            break
        start = max(0, end - overlap)
    return chunks


def ingest_documents_memory(docs: Iterable[dict], *, max_chars: int = 1200, overlap: int = 120) -> List[Dict]:
    """Ingest in-memory documents.

    docs: iterable of {filename: str, content: bytes} OR {filename: str, text: str}
    """
    out: List[Dict] = []
    for d in docs:
        name = d.get('filename') or 'document'
        if 'text' in d and isinstance(d['text'], str):
            raw = d['text']
        else:
            content = d.get('content') or b''
            # Pick loader by naive extension
            if str(name).lower().endswith('.pdf'):
                raw = _load_pdf_text_bytes(content)
            else:
                raw = _load_text_bytes(content)
        norm = normalize_text(raw)
        # Optional redaction hook (PII)
        try:
            from src.core.redaction import scrub_text  # type: ignore
            norm = scrub_text(norm)
        except Exception:
            pass
        parts = chunk_text(norm, max_chars=max_chars, overlap=overlap)
        for idx, p in enumerate(parts):
            out.append({
                'id': str(uuid.uuid4()),
                'source_file': name,
                'chunk_index': idx,
                'text': p,
                'char_len': len(p),
            })
    return out

__all__ = ['ingest_documents_memory', 'normalize_text', 'chunk_text']
