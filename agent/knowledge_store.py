"""KnowledgeStore: FAISS-backed retrieval when possible with robust fallbacks.

This class attempts to use FAISS + NIM embeddings when available. If FAISS or
NIM is not available it falls back to a deterministic, fast embedding shim and
brute-force similarity search so the retrieval path remains usable in CI and
local development.
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import List, Optional, Tuple

try:
    import faiss
except Exception:
    faiss = None  # type: ignore

try:
    import numpy as np
except Exception:
    np = None  # type: ignore

from .nim_client import NIMClient
try:
    from .aws_client import SageMakerClient
except Exception:
    SageMakerClient = None  # type: ignore

logger = logging.getLogger("codeguardian.knowledge_store")


def _mock_embed(texts: List[str], dim: int = 128) -> List[List[float]]:
    """Deterministic hash-based embeddings used when NIM/numpy/faiss are missing.

    Produces a vector of `dim` floats derived from SHA256 bytes.
    """
    out = []
    for t in texts:
        h = hashlib.sha256(t.encode("utf-8")).digest()
        # expand bytes if needed
        buf = h
        while len(buf) < dim:
            buf += hashlib.sha256(buf).digest()
        # convert to floats in [0,1)
        vals = [b / 255.0 for b in buf[:dim]]
        # normalize
        if np is not None:
            arr = np.array(vals, dtype="float32")
            norm = np.linalg.norm(arr) + 1e-12
            out.append((arr / norm).tolist())
        else:
            # simple L2 norm
            s = sum(v * v for v in vals) ** 0.5 + 1e-12
            out.append([v / s for v in vals])
    return out


class KnowledgeStore:
    def __init__(self, entries: Optional[List[Tuple[str, str]]] = None, index_path: Optional[str] = None):
        """entries: list of (id, text) tuples

        index_path: optional path to persist/load a FAISS index and metadata.
        """
        self.entries = entries or []
        self.ids = [e[0] for e in self.entries]
        self.texts = [e[1] for e in self.entries]
        self.index = None
        self._embeddings = None  # cached numpy array if built
        self.nim = None
        self.index_path = index_path

        # attempt to initialize NIM client if embedding endpoint configured
        self.nim = None
        try:
            self.nim = NIMClient()
        except Exception:
            # try SageMaker client as a fallback for embeddings
            try:
                if SageMakerClient is not None:
                    self.nim = SageMakerClient()
            except Exception:
                self.nim = None

        # try to load persisted index
        if self.index_path and faiss:
            try:
                self.load_index(self.index_path)
            except Exception:
                logger.debug("No persisted index found at %s", self.index_path)

        # try to build FAISS index if possible
        if self.index is None and faiss and self.nim and getattr(self.nim, "embedding_url", None):
            try:
                self.build_index()
            except Exception:
                logger.exception("Failed to build FAISS index; will use brute-force fallback")

    def build_index(self, force: bool = False):
        """Build FAISS index (or rebuild). If NIM is not available, falls back to
        deterministic mock embeddings so index can still be constructed.
        """
        texts = self.texts
        embs = self._compute_embeddings(texts)
        if np is None:
            raise RuntimeError("numpy required to build index")
        arr = np.array(embs).astype("float32")
        d = arr.shape[1]
        self.index = faiss.IndexFlatL2(d)
        self.index.add(arr)
        self._embeddings = arr
        # optionally persist
        if self.index_path and faiss:
            try:
                faiss.write_index(self.index, self.index_path)
            except Exception:
                logger.exception("Failed to persist FAISS index")

    def _compute_embeddings(self, texts: List[str]) -> List[List[float]]:
        if self.nim:
            try:
                return self.nim.embed(texts)
            except Exception:
                logger.exception("NIM embedding failed; falling back to mock embeddings")
        # fallback deterministic embeddings
        return _mock_embed(texts)

    def save_index(self, path: str):
        if not faiss or self.index is None:
            raise RuntimeError("No FAISS index to save")
        faiss.write_index(self.index, path)
        # write metadata (ids/texts)
        meta_path = path + ".meta"
        try:
            import json

            with open(meta_path, "w", encoding="utf-8") as fh:
                json.dump({"ids": self.ids, "texts": self.texts}, fh, ensure_ascii=False)
        except Exception:
            logger.exception("Failed to write metadata for index")

    def load_index(self, path: str):
        if not faiss:
            raise RuntimeError("faiss is required to load index")
        self.index = faiss.read_index(path)
        meta_path = path + ".meta"
        if os.path.exists(meta_path):
            import json

            with open(meta_path, "r", encoding="utf-8") as fh:
                meta = json.load(fh)
                self.ids = meta.get("ids", [])
                self.texts = meta.get("texts", [])

    def query(self, query_text: str, top_k: int = 3) -> List[Tuple[str, float, str]]:
        """Return up to top_k (id, score, text) matching the query.

        If a FAISS index is available a nearest-neighbor search is performed.
        Otherwise we compute embeddings (NIM or mock) and run a brute-force
        similarity search (cosine similarity) over the vectors.
        """
        # FAISS path
        if self.index is not None and faiss and np is not None:
            try:
                q_emb = self._compute_embeddings([query_text])[0]
                qv = np.array(q_emb).astype("float32").reshape(1, -1)
                D, I = self.index.search(qv, top_k)
                results = []
                for dist, idx in zip(D[0], I[0]):
                    if idx < 0 or idx >= len(self.ids):
                        continue
                    results.append((self.ids[idx], float(dist), self.texts[idx]))
                return results
            except Exception:
                logger.exception("Embedding/FAISS query failed; falling back to brute-force")

        # Brute-force embedding + similarity
        embs = self._compute_embeddings(self.texts)
        q_emb = self._compute_embeddings([query_text])[0]
        if np is not None:
            arr = np.array(embs).astype("float32")
            qv = np.array(q_emb).astype("float32")
            # cosine similarity
            sims = (arr @ qv) / (np.linalg.norm(arr, axis=1) * (np.linalg.norm(qv) + 1e-12) + 1e-12)
            idxs = list(reversed(np.argsort(sims)))
            results = []
            for i in idxs[:top_k]:
                results.append((self.ids[i], float(sims[i]), self.texts[i]))
            return results
        else:
            # pure python similarity
            def dot(a, b):
                return sum(x * y for x, y in zip(a, b))

            def norm(v):
                return sum(x * x for x in v) ** 0.5 + 1e-12

            sims = [dot(q_emb, e) / (norm(q_emb) * norm(e)) for e in embs]
            ranked = sorted(range(len(sims)), key=lambda i: sims[i], reverse=True)
            return [(self.ids[i], float(sims[i]), self.texts[i]) for i in ranked[:top_k]]

    def add_entry(self, eid: str, text: str):
        self.ids.append(eid)
        self.texts.append(text)
        # best-effort: update FAISS index incrementally if possible
        try:
            if self.index is not None and faiss and np is not None:
                emb = self._compute_embeddings([text])
                arr = np.array(emb).astype("float32")
                self.index.add(arr)
                # update embeddings cache
                if self._embeddings is not None:
                    self._embeddings = np.vstack([self._embeddings, arr])
        except Exception:
            logger.exception("Failed to update FAISS index")


def _cli():
    """Simple CLI to build and persist a FAISS index for the provided KB entries.

    Example:
      python -m agent.knowledge_store --build --out data/index.faiss
    """
    import argparse

    parser = argparse.ArgumentParser(description="KnowledgeStore index utility")
    parser.add_argument("--build", action="store_true", help="Build a FAISS index from the bundled KB entries")
    parser.add_argument("--out", help="Path to write FAISS index (e.g. data/index.faiss)")
    parser.add_argument("--force", action="store_true", help="Force rebuild even if index exists")
    args = parser.parse_args()

    if not args.build:
        parser.print_help()
        return

    # import the static KB to build entries
    try:
        from .knowledge_base import KnowledgeBase

        static = KnowledgeBase()
        entries = [(k, v.get("summary", "")) for k, v in static._kb.items()]
    except Exception:
        print("Failed to load knowledge base entries")
        return

    ks = KnowledgeStore(entries=entries, index_path=args.out)
    # if FAISS available, build and save
    if faiss and np is not None:
        try:
            if args.force or ks.index is None:
                print("Building FAISS index...")
                ks.build_index()
            if args.out:
                print(f"Saving index to {args.out}")
                ks.save_index(args.out)
            print("Done.")
        except Exception as e:
            print("Failed to build/save index:", e)
    else:
        print("FAISS or numpy not available; cannot build index. Use --mock in eval scripts for CI.")


if __name__ == "__main__":
    _cli()
