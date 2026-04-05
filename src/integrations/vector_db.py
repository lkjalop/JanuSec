"""Semantic log search helper using ChromaDB when available."""
from __future__ import annotations

from typing import Any, Dict, List

try:  # pragma: no cover
    import chromadb
    from sentence_transformers import SentenceTransformer
except Exception:  # fallback shim
    chromadb = None  # type: ignore
    SentenceTransformer = None  # type: ignore


class VectorLogSearch:
    def __init__(self):
        self.client = chromadb.Client() if chromadb else None  # type: ignore
        self.collection = (
            self.client.get_or_create_collection("security_logs")
            if self.client
            else None
        )
        self.model = SentenceTransformer("all-MiniLM-L6-v2") if SentenceTransformer else None  # type: ignore

    def index_logs(self, logs: List[Dict[str, Any]]) -> None:
        if not logs or not self.collection or not self.model:
            return
        documents = [str(log.get("message") or "") for log in logs]
        ids = [str(log.get("id") or i) for i, log in enumerate(logs)]
        metadatas = [log.get("metadata") or {} for log in logs]
        embeddings = self.model.encode(documents).tolist()
        self.collection.add(
            embeddings=embeddings,
            documents=documents,
            ids=ids,
            metadatas=metadatas,
        )

    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        if not self.collection:
            # fallback: simple keyword search from metadata documents stored in-memory
            return []
        if self.model:
            query_embedding = self.model.encode([query]).tolist()
            res = self.collection.query(query_embeddings=query_embedding, n_results=top_k)
        else:
            res = self.collection.query(query_texts=[query], n_results=top_k)
        out = []
        for i in range(len(res.get("ids", [[]])[0])):
            out.append(
                {
                    "id": res["ids"][0][i],
                    "message": res["documents"][0][i],
                    "metadata": res["metadatas"][0][i],
                    "distance": res["distances"][0][i] if res.get("distances") else None,
                }
            )
        return out


VECTOR_LOG_SEARCH = VectorLogSearch()

__all__ = ["VectorLogSearch", "VECTOR_LOG_SEARCH"]
