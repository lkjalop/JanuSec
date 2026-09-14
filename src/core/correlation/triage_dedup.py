from __future__ import annotations
from typing import List, Dict, Any, Tuple, Callable
import hashlib
import math
import random
from collections import Counter, defaultdict

# Optional sklearn-backed vectorizer for better clustering quality
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_distances
    _SKLEARN_AVAILABLE = True
except Exception:
    TfidfVectorizer = None  # type: ignore
    cosine_distances = None  # type: ignore
    _SKLEARN_AVAILABLE = False


# Lightweight hash bucketing for quick partitioning
def bucket_by_hash(rows: List[Dict[str, Any]], key_fields: List[str], bucket_bits: int = 12) -> Dict[int, List[Dict[str, Any]]]:
    """Bucket rows by a truncated SHA1 of concatenated key fields."""
    out: Dict[int, List[Dict[str, Any]]] = {}
    nibble_len = max(1, bucket_bits // 4)
    for r in rows:
        parts = []
        for k in key_fields:
            parts.append(str(r.get(k, '')).strip().lower())
        s = '|'.join(parts)
        h = hashlib.sha1(s.encode('utf-8')).hexdigest()
        b = int(h[:nibble_len], 16)
        out.setdefault(b, []).append(r)
    return out


def _char_ngrams(s: str, n: int = 3) -> List[str]:
    s2 = f"^^{s}^^"
    return [s2[i:i+n] for i in range(len(s2) - n + 1)]


def _vectorize_rows(rows: List[Dict[str, Any]], fields: List[str]) -> List[Dict[str, float]]:
    """Simple sparse vector representation using character 3-grams counts across fields."""
    docs = []
    for r in rows:
        text_parts = []
        for f in fields:
            v = r.get(f)
            if v is None:
                continue
            text_parts.append(str(v))
        docs.append(' '.join(text_parts))
    # build vocabulary of ngrams
    vocab = {}
    df = Counter()
    doc_ngrams = []
    for d in docs:
        ngrams = _char_ngrams(d)
        doc_ngrams.append(ngrams)
        unique = set(ngrams)
        for g in unique:
            df[g] += 1
    # keep ngrams that appear in at least one doc (all do) but limit vocab size
    for i, g in enumerate(sorted(df.keys(), key=lambda x: (-df[x], x))):
        vocab[g] = i
    vectors: List[Dict[str, float]] = []
    N = max(1, len(docs))
    for ngrams in doc_ngrams:
        ctr = Counter(ngrams)
        vec: Dict[str, float] = {}
        for g, cnt in ctr.items():
            # TF-IDF style weighting (tf * idf)
            tf = cnt
            idf = math.log(N / (1 + df.get(g, 0)))
            vec[g] = tf * idf
        vectors.append(vec)
    return vectors


def _sklearn_vectorize(rows: List[Dict[str, Any]], fields: List[str]):
    """Return (matrix, feature_names) using sklearn TF-IDF over concatenated fields."""
    docs = []
    for r in rows:
        parts = []
        for f in fields:
            v = r.get(f)
            if v is None:
                continue
            parts.append(str(v))
        docs.append(' '.join(parts))
    vec = TfidfVectorizer(analyzer='char_wb', ngram_range=(3,3), max_features=2000)
    X = vec.fit_transform(docs)
    return X, vec.get_feature_names_out()


def _to_sparse_dict(sparse_row) -> Dict[int, float]:
    """Convert sklearn sparse row or vector to a dict index->value."""
    try:
        # CSR row
        coo = sparse_row.tocoo()
        return {int(c): float(v) for c, v in zip(coo.col, coo.data)}
    except Exception:
        try:
            # dense array
            arr = sparse_row.toarray().ravel()
            return {i: float(v) for i, v in enumerate(arr) if v != 0.0}
        except Exception:
            return {}


def _cosine_distance(a: Dict[str, float], b: Dict[str, float]) -> float:
    # treat vectors as sparse dicts
    num = 0.0
    for k, v in a.items():
        bv = b.get(k)
        if bv is not None:
            num += v * bv
    denom_a = math.sqrt(sum(v * v for v in a.values()))
    denom_b = math.sqrt(sum(v * v for v in b.values()))
    if denom_a == 0 or denom_b == 0:
        return 1.0
    cos = num / (denom_a * denom_b)
    return 1.0 - max(-1.0, min(1.0, cos))


def mini_batch_k_medoids(rows: List[Dict[str, Any]], k: int = 3, fields: List[str] | None = None, batch_size: int = 50, max_iters: int = 100, random_state: int | None = None, distance_fn: Callable[[Dict[str, float], Dict[str, float]], float] | None = None) -> Tuple[List[Dict[str, Any]], List[int]]:
    """Mini-batch k-medoids clustering.

    - Vectorizes rows into sparse char-3gram TF-IDF vectors across `fields`.
    - Selects medoids from actual rows; updates medoids by sampling batches and
      choosing the row with minimal total distance to other assigned members.
    - Returns list of medoid rows and an assignment list parallel to `rows`.
    """
    if not rows:
        return [], []
    if fields is None:
        # choose common useful fields
        fields = ['user', 'host', 'process', 'file_hash', 'sha256', 'domain']
    if random_state is not None:
        random.seed(random_state)

    # Prefer sklearn TF-IDF vectors when available for better distance estimates
    use_sklearn = _SKLEARN_AVAILABLE
    if use_sklearn:
        try:
            X, feats = _sklearn_vectorize(rows, fields)
        except Exception:
            use_sklearn = False
    if not use_sklearn:
        vectors = _vectorize_rows(rows, fields)
    n = len(rows)
    k = min(k, n)
    # initialize medoid indices deterministically
    medoid_idxs = []
    start = int(hashlib.sha1(str(n).encode('utf-8')).hexdigest(), 16)
    i = start % n
    while len(medoid_idxs) < k:
        if i not in medoid_idxs:
            medoid_idxs.append(i)
        i = (i + 1) % n

    distance_fn = distance_fn or _cosine_distance
    assignments = [0] * n

    for iteration in range(max_iters):
        # assign all points to nearest medoid
        changed = False
        for idx in range(n):
            best_m = None
            best_d = None
            for mi, midx in enumerate(medoid_idxs):
                if use_sklearn:
                    # compute cosine distance between sparse rows
                    try:
                        d = float(cosine_distances(X[idx], X[midx])[0][0])
                    except Exception:
                        d = distance_fn(_to_sparse_dict(X[idx]), _to_sparse_dict(X[midx])) if not isinstance(X, list) else distance_fn(vectors[idx], vectors[midx])
                else:
                    d = distance_fn(vectors[idx], vectors[midx])
                if best_m is None or d < best_d:
                    best_m = mi; best_d = d
            if assignments[idx] != best_m:
                assignments[idx] = best_m
                changed = True
        # sample a mini-batch of indices to consider medoid updates
        batch = random.sample(range(n), min(batch_size, n))
        updated = False
        for mi in range(len(medoid_idxs)):
            # collect indices assigned to this medoid in the batch
            members = [i for i in batch if assignments[i] == mi]
            if not members:
                continue
            # compute pairwise distance sums and pick the medoid candidate minimizing sum
            best_candidate = None
            best_score = None
            for cand in members:
                s = 0.0
                for other in members:
                    if use_sklearn:
                        try:
                            s += float(cosine_distances(X[cand], X[other])[0][0])
                        except Exception:
                            s += distance_fn(vectors[cand], vectors[other])
                    else:
                        s += distance_fn(vectors[cand], vectors[other])
                if best_score is None or s < best_score:
                    best_score = s
                    best_candidate = cand
            if best_candidate is not None and medoid_idxs[mi] != best_candidate:
                medoid_idxs[mi] = best_candidate
                updated = True
        if not changed and not updated:
            break

    medoids = [rows[i] for i in medoid_idxs]
    return medoids, assignments


if __name__ == '__main__':
    # quick smoke test
    rows = [
        {'user': 'alice', 'sha256': 'a' * 64, 'host': 'h1'},
        {'user': 'bob', 'sha256': 'b' * 64, 'host': 'h2'},
        {'user': 'alice', 'sha256': 'a' * 64, 'host': 'h3'},
    ]
    print('buckets', bucket_by_hash(rows, ['user', 'sha256']))
    print('medoids', mini_batch_k_medoids(rows, k=2, random_state=42))
