import json
from pathlib import Path

from src.core.correlation.rules.week1.office_macro_chain_enriched import office_macro_chain_enriched


def _load(path: str):
    p = Path(path)
    return json.loads(p.read_text(encoding='utf-8'))


def test_office_macro_chain_enriched_isolated():
    evt = _load('tests/data/office_macro_chain_enriched_event.json')
    assert office_macro_chain_enriched(evt) is True
