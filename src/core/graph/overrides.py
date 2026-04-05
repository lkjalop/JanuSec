from __future__ import annotations
from typing import Any

def set_hopgraph_override(hg: Any) -> None:
    try:
        from src.enrichment import consumer as _consumer
        _consumer.set_hopgraph_override(hg)
    except Exception:
        pass

def clear_hopgraph_override() -> None:
    try:
        from src.enrichment import consumer as _consumer
        _consumer.clear_hopgraph_override()
    except Exception:
        pass

def set_crq_persistence(persist: Any) -> None:
    try:
        from src.crq import fair_shadow as _fs
        _fs.set_crq_persistence(persist)
    except Exception:
        pass
