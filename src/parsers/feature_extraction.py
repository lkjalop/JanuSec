from __future__ import annotations

from typing import List, Dict, Any
import math
from collections import Counter
from src.parsers.tfidf_utils import load_corpus, score_document


def ngrams(text: str, n: int = 3) -> List[str]:
    s = text.replace('\n',' ').strip()
    tokens = s.split()
    if len(tokens) < n:
        return tokens
    out = []
    for i in range(len(tokens)-n+1):
        out.append(' '.join(tokens[i:i+n]))
    return out


def tfidf_vector(docs: List[str]) -> List[Dict[str, float]]:
    # very small TF-IDF: compute TF and IDF across docs and return top tokens per doc
    docs_tokens = [Counter(d.split()) for d in docs]
    df = Counter()
    for ct in docs_tokens:
        for t in ct:
            df[t] += 1
    N = len(docs)
    out = []
    for ct in docs_tokens:
        doc_tf = {}
        for t, c in ct.items():
            idf = math.log((N+1) / (df.get(t,1)))
            doc_tf[t] = c * idf
        out.append(doc_tf)
    return out


def tfidf_score_text(text: str, corpus_name: str = 'default') -> Dict[str, float]:
    """Score a single document against a persisted corpus using tfidf_utils."""
    c = load_corpus(corpus_name)
    if not c:
        return {}
    return score_document(text, corpus_name)


def entropy_of_bytes(b: bytes) -> float:
    if not b:
        return 0.0
    cnt = Counter(b)
    total = len(b)
    ent = 0.0
    for v in cnt.values():
        p = v/total
        ent -= p * math.log2(p)
    return ent


def beacon_interval(timestamps: List[float]) -> Dict[str, Any]:
    if not timestamps:
        return {'mean_interval': None, 'std_interval': None}
    intervals = [timestamps[i+1]-timestamps[i] for i in range(len(timestamps)-1)]
    if not intervals:
        return {'mean_interval': None, 'std_interval': None}
    mean = sum(intervals)/len(intervals)
    var = sum((x-mean)**2 for x in intervals)/len(intervals)
    return {'mean_interval': mean, 'std_interval': math.sqrt(var)}


def detect_ngram_beacon(ngrams_list: List[str], host_timestamps: Dict[str, List[float]], min_occurrences: int = 5, window_seconds: float = 3600.0) -> Dict[str, Any]:
    """Detect n-grams that appear repetitively across host timestamps.
    - `ngrams_list` is a list of n-gram tokens observed.
    - `host_timestamps` maps host -> list of timestamps where these ngrams were seen.
    Returns candidates with simple periodicity metrics.
    """
    counts = Counter(ngrams_list)
    candidates = {g: counts[g] for g in counts if counts[g] >= min_occurrences}
    results: Dict[str, Any] = {}
    for g in candidates:
        # collect all timestamps across hosts for this ngram
        ts_all = []
        for host, ts_list in host_timestamps.items():
            # we assume host_timestamps are filtered per ngram in caller usage
            ts_all.extend(ts_list)
        ts_all.sort()
        if len(ts_all) < 2:
            continue
        intervals = [ts_all[i+1]-ts_all[i] for i in range(len(ts_all)-1)]
        mean = sum(intervals)/len(intervals)
        variance = sum((x-mean)**2 for x in intervals)/len(intervals)
        results[g] = {'occurrences': counts[g], 'mean_interval': mean, 'std_interval': math.sqrt(variance)}
    return results
