"""Evaluate embedding model via NIM + FAISS

Builds embeddings for a small sample of labeled texts, constructs a FAISS
index, and computes precision@k and MRR for sample queries.

Usage: python scripts/eval_embeddings.py

Requirements: numpy, faiss (optional but recommended), and NIM credentials in env
"""
import os
import time
import json

import argparse
import hashlib
import math
from typing import List

try:
    import faiss
except Exception:
    faiss = None

try:
    import numpy as np
except Exception:
    np = None

from agent.nim_client import NIMClient

SAMPLES = [
    ("secret in code", "This file contains an API key hardcoded as a string."),
    ("sql injection", "Query constructed with string concatenation using user input."),
    ("deprecated hash", "Use of hashlib.md5 to compute checksums"),
    ("suspicious subprocess", "Calling subprocess with shell=True on user input"),
    ("regex catastrophe", "Complex regex with nested quantifiers causing backtracking"),
]

QUERIES = [
    ("how to avoid hardcoded secrets", "secret in code"),
    ("prevent sql injection", "sql injection"),
    ("replace md5", "deprecated hash"),
]


def build_embeddings(texts, client: NIMClient):
    print("Requesting embeddings for", len(texts), "items...")
    try:
        return client.embed(texts)
    except Exception:
        print("NIM client embed failed; falling back to deterministic mock embeddings")
        return _mock_embed(texts)


def _mock_embed(texts: List[str], dim: int = 128):
    out = []
    for t in texts:
        h = hashlib.sha256(t.encode("utf-8")).digest()
        buf = h
        while len(buf) < dim:
            buf += hashlib.sha256(buf).digest()
        vals = [b / 255.0 for b in buf[:dim]]
        if np is not None:
            arr = np.array(vals, dtype="float32")
            norm = np.linalg.norm(arr) + 1e-12
            out.append((arr / norm).tolist())
        else:
            s = sum(v * v for v in vals) ** 0.5 + 1e-12
            out.append([v / s for v in vals])
    return out


def build_faiss_index(embs):
    if faiss is None or np is None:
        raise RuntimeError("faiss and numpy are required to build a FAISS index")
    arr = np.array(embs).astype('float32')
    d = arr.shape[1]
    idx = faiss.IndexFlatL2(d)
    idx.add(arr)
    return idx


def precision_at_k(index, qvec, truths, k=3):
    # index may be a FAISS index or a tuple (embs_array)
    if faiss and hasattr(index, 'search'):
        D, I = index.search(qvec, k)
        hits = I[0].tolist()
    else:
        # brute-force: qvec is numpy array of shape (1,d)
        arr = index
        if np is None:
            return 0.0
        sims = (arr @ qvec[0]) / (np.linalg.norm(arr, axis=1) * (np.linalg.norm(qvec[0]) + 1e-12) + 1e-12)
        hits = list(reversed(np.argsort(sims)))[:k]
    for t in truths:
        if t in hits:
            return 1.0
    return 0.0


def mrr(index, qvec, truths, k=10):
    if faiss and hasattr(index, 'search'):
        D, I = index.search(qvec, k)
        ranks = I[0].tolist()
    else:
        arr = index
        if np is None:
            return 0.0
        sims = (arr @ qvec[0]) / (np.linalg.norm(arr, axis=1) * (np.linalg.norm(qvec[0]) + 1e-12) + 1e-12)
        ranks = list(reversed(np.argsort(sims)))[:k]
    for i, r in enumerate(ranks, start=1):
        if r in truths:
            return 1.0 / i
    return 0.0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mock", action="store_true", help="Force mock embeddings instead of NIM (useful for CI)")
    args = parser.parse_args()

    client = None
    try:
        client = NIMClient()
    except Exception:
        client = None

    texts = [s[1] for s in SAMPLES]
    ids = [s[0] for s in SAMPLES]

    # get embeddings (NIM if available and not forced mock)
    if args.mock or client is None:
        embs = _mock_embed(texts)
    else:
        embs = build_embeddings(texts, client)

    # build index: prefer FAISS, otherwise use numpy array as brute-force store
    if faiss and np is not None:
        try:
            idx = build_faiss_index(embs)
            index_is_faiss = True
        except Exception:
            print("Failed to build FAISS index; falling back to brute-force array")
            idx = np.array(embs).astype('float32')
            index_is_faiss = False
    else:
        idx = np.array(embs).astype('float32') if np is not None else embs
        index_is_faiss = False

    # prepare a mapping from id to index position
    id_to_pos = {ids[i]: i for i in range(len(ids))}

    p_at_k_total = 0.0
    mrr_total = 0.0
    for q_text, true_id in QUERIES:
        if args.mock or client is None:
            q_emb = _mock_embed([q_text])
        else:
            try:
                q_emb = build_embeddings([q_text], client)
            except Exception:
                q_emb = _mock_embed([q_text])

        if np is not None:
            qvec = np.array(q_emb).astype('float32').reshape(1, -1)
        else:
            qvec = q_emb

        p = precision_at_k(idx, qvec, [id_to_pos[true_id]], k=3)
        r = mrr(idx, qvec, [id_to_pos[true_id]], k=10)
        print(f"Query: {q_text} -> precision@3={p:.3f}, mrr={r:.3f}")
        p_at_k_total += p
        mrr_total += r

    print(f"Average precision@3: {p_at_k_total/len(QUERIES):.3f}")
    print(f"Average MRR: {mrr_total/len(QUERIES):.3f}")


if __name__ == '__main__':
    main()
