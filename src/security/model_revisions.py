"""Immutable model revisions resolved from the publishers on 2026-09-14.
Pins establish reproducibility, not a model quality or security certification.
"""
import re
PINNED_REVISIONS = {'sentence-transformers/all-MiniLM-L6-v2': '1110a243fdf4706b3f48f1d95db1a4f5529b4d41', 'sentence-transformers/paraphrase-MiniLM-L3-v2': '4ca70771034acceecb2e72475f72050fcdde4ddc', 'roberta-base': 'e2da8e2f811d1448a5b465c236feacd80ffbac7b', 'microsoft/deberta-v3-base': '8ccc9b6f36199bec6961081d44eb72fb3f7353f3', 'mistralai/Mistral-7B-Instruct-v0.2': '63a8b081895390a26e140280378bc85ec8bce07a'}

def model_revision(model_id: str, revision: str | None = None) -> str:
    value = revision or PINNED_REVISIONS.get(model_id)
    if not value or not re.fullmatch(r'[0-9a-f]{40}', value):
        raise ValueError('An immutable model revision is required')
    return value
