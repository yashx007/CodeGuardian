"""KnowledgeStore: optional FAISS-backed retrieval over KB entries.

This component is optional. If `faiss` and a NIM embedding endpoint are
available it will build an index; otherwise it falls back to in-memory linear
scan using simple text matching.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Tuple

try:
    import faiss
except Exception:
    faiss = None  # type: ignore

from .nim_client import NIMClient

logger = logging.getLogger("codeguardian.knowledge_store")


class KnowledgeStore:
    def __init__(self, entries: Optional[List[Tuple[str, str]]] = None):
        """entries: list of (id, text) tuples"""
        self.entries = entries or []
        self.index = None
        self.ids = [e[0] for e in self.entries]
        self.texts = [e[1] for e in self.entries]
        self.nim = None
        # attempt to initialize NIM client if embedding endpoint configured
        try:
            self.nim = NIMClient()
        except Exception:
            self.nim = None

        # try to build FAISS index if possible
        if faiss and self.nim and getattr(self.nim, "embedding_url", None):
            try:
                self._build_index()
            except Exception:
                logger.exception("Failed to build FAISS index; will use linear scan")
                self.index = None

    def _build_index(self):
        # obtain embeddings for texts
        if not self.nim:
            raise RuntimeError("No embedding client available")
        embs = self.nim.embed(self.texts)
        import numpy as np

        arr = np.array(embs).astype("float32")
        d = arr.shape[1]
        self.index = faiss.IndexFlatL2(d)
        self.index.add(arr)

    def query(self, query_text: str, top_k: int = 3) -> List[Tuple[str, float, str]]:
        """Return up to top_k (id, score, text) matching the query.

        If FAISS index is not available this falls back to a simple substring
        relevance score.
        """
        if self.index is not None and self.nim:
            try:
                q_emb = self.nim.embed([query_text])[0]
                import numpy as np

                qv = np.array(q_emb).astype("float32").reshape(1, -1)
                D, I = self.index.search(qv, top_k)
                results = []
                for dist, idx in zip(D[0], I[0]):
                    if idx < 0 or idx >= len(self.ids):
                        continue
                    results.append((self.ids[idx], float(dist), self.texts[idx]))
                return results
            except Exception:
                logger.exception("Embedding/FAISS query failed; falling back to linear")

        # linear fallback: simple substring matching with heuristic score
        res = []
        qt = query_text.lower()
        for i, t in enumerate(self.texts):
            score = 0.0
            tl = t.lower()
            if qt in tl:
                score = 1.0
            else:
                # partial token overlap
                qtokens = set(qt.split())
                ttokens = set(tl.split())
                overlap = qtokens & ttokens
                score = len(overlap) / max(1, len(qtokens))
            res.append((self.ids[i], score, t))
        res.sort(key=lambda x: x[1], reverse=True)
        return res[:top_k]

    def add_entry(self, eid: str, text: str):
        self.ids.append(eid)
        self.texts.append(text)
        # best-effort: re-build index if possible
        try:
            if self.index is not None:
                self._build_index()
        except Exception:
            logger.exception("Failed to update FAISS index")
