"""Simple connectivity test for NVIDIA NIM embedding and inference endpoints.

This script uses the existing `agent.nim_client.NIMClient` and the environment
variables you configured (`NIM_BASE_URL`, `NIM_API_KEY_EMBEDDING`, etc.).

It will print concise, sanitized output so you can confirm connectivity.

Run from the repo root: python scripts/test_nim_connectivity.py
"""

import json
import traceback
from agent.nim_client import NIMClient


def sanitize(s: str, max_len: int = 300) -> str:
    if s is None:
        return "<empty>"
    s = str(s)
    if len(s) > max_len:
        return s[:max_len] + "... [truncated]"
    return s


def main():
    client = NIMClient()
    print("Using inference_url:", client.inference_url)
    print("Using embedding_url:", client.embedding_url)
    print()

    # Test embedding
    try:
        print("Testing embeddings with sample text ['hello world']...")
        embs = client.embed(["hello world"])
        print("Received embeddings count:", len(embs))
        if len(embs) > 0:
            print("Embedding vector length:", len(embs[0]))
            print("First 8 dims:", embs[0][:8])
    except Exception as e:
        print("Embedding test failed:")
        traceback.print_exc()

    print()

    # Test inference
    try:
        prompt = "Provide a one-sentence explanation of SQL injection."
        print("Testing inference with prompt:\n", prompt)
        out = client.explain(prompt, max_tokens=128)
        print("Inference output (sanitized):")
        print(sanitize(out, 1000))
    except Exception as e:
        print("Inference test failed:")
        traceback.print_exc()


if __name__ == '__main__':
    main()
