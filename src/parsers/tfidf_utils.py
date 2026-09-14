"""TF-IDF utilities for corpus creation and scoring.
Provides a simple persistent corpus index under data/tfidf/*.json
"""
from __future__ import annotations
import math
import json
from pathlib import Path
from typing import List, Dict

TFIDF_DIR = Path('data') / 'tfidf'
TFIDF_DIR.mkdir(parents=True, exist_ok=True)

def build_corpus(documents: List[str], corpus_name: str = 'default') -> None:
    """Build and persist TF and DF counts for given documents."""
    tf_list: List[Dict[str, int]] = []
    df: Dict[str, int] = {}
    for doc in documents:
        toks = [t for t in doc.lower().split() if t]
        tf: Dict[str, int] = {}
        seen = set()
        for t in toks:
            tf[t] = tf.get(t, 0) + 1
            if t not in seen:
                df[t] = df.get(t, 0) + 1
                seen.add(t)
        tf_list.append(tf)
    # persist
    payload = {'tf_list': tf_list, 'df': df, 'doc_count': len(documents)}
    p = TFIDF_DIR / f"{corpus_name}.json"
    p.write_text(json.dumps(payload))

def load_corpus(corpus_name: str = 'default') -> Dict:
    p = TFIDF_DIR / f"{corpus_name}.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text())

def score_document(text: str, corpus_name: str = 'default') -> Dict[str, float]:
    c = load_corpus(corpus_name)
    if not c:
        return {}
    tf_list = c.get('tf_list', [])
    df = c.get('df', {})
    N = max(1, int(c.get('doc_count', len(tf_list))))
    toks = [t for t in text.lower().split() if t]
    tf: Dict[str, int] = {}
    for t in toks:
        tf[t] = tf.get(t, 0) + 1
    scores: Dict[str, float] = {}
    for t, cnt in tf.items():
        idf = math.log((1 + N) / (1 + df.get(t, 0))) + 1.0
        scores[t] = cnt * idf
    return scores
