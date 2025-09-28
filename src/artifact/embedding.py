from __future__ import annotations
from typing import List, Dict, Any, Optional
import threading, math, random

try:
    from sentence_transformers import SentenceTransformer
except Exception:  # pragma: no cover
    SentenceTransformer = None  # type: ignore

class EmbeddingProvider:
    def __init__(self, model_name: str = 'all-MiniLM-L6-v2'):
        self.model_name = model_name
        self._model = None
        self._lock = threading.RLock()
        if SentenceTransformer:
            try:
                self._model = SentenceTransformer(model_name)
            except Exception:
                self._model = None

    def embed_texts(self, texts: List[str]) -> List[List[float]]:
        if self._model:
            embs = self._model.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
            return [e.tolist() for e in embs]
        # fallback deterministic pseudo-embedding
        out = []
        for t in texts:
            random.seed(hash(t) % (2**32 -1))
            out.append([ (random.random()*2-1) for _ in range(32)])
        return out

class SimpleClusterManager:
    def __init__(self, similarity_threshold: float = 0.83):
        self.similarity_threshold = similarity_threshold
        self.centroids: Dict[str, List[float]] = {}
        self.cluster_counts: Dict[str, int] = {}
        self._lock = threading.RLock()
        self._next_id = 1

    @staticmethod
    def cosine(a: List[float], b: List[float]) -> float:
        num = sum(x*y for x,y in zip(a,b))
        da = math.sqrt(sum(x*x for x in a)) or 1.0
        db = math.sqrt(sum(x*x for x in b)) or 1.0
        return num/(da*db)

    def assign(self, vec: List[float]) -> str:
        with self._lock:
            best_id = None
            best_sim = -1.0
            for cid, cvec in self.centroids.items():
                sim = self.cosine(vec, cvec)
                if sim > best_sim:
                    best_sim = sim; best_id = cid
            if best_id and best_sim >= self.similarity_threshold:
                # update centroid incremental
                count = self.cluster_counts[best_id]
                new_centroid = [ (c*count + v)/(count+1) for c,v in zip(self.centroids[best_id], vec)]
                self.centroids[best_id] = new_centroid
                self.cluster_counts[best_id] = count + 1
                return best_id
            # new cluster
            cid = f"c{self._next_id}"
            self._next_id += 1
            self.centroids[cid] = vec
            self.cluster_counts[cid] = 1
            return cid

    def stats(self, cid: str) -> Dict[str, Any]:
        return {'size': self.cluster_counts.get(cid,0)}
