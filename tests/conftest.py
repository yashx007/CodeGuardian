import json
import hashlib
from typing import List


class FakeNIMClient:
    """A lightweight fake NIM client for tests.

    - embed(texts) returns deterministic normalized vectors (dim=128)
    - explain(prompt, ...) returns a short JSON string with explanation/fix/refs
    """

    def __init__(self, *args, **kwargs):
        # Provide non-empty endpoints so LLMClient treats this fake as "online available"
        self.inference_url = "fake://inference"
        self.embedding_url = "fake://embedding"

    def embed(self, texts: List[str]) -> List[List[float]]:
        dim = 128
        out = []
        for t in texts:
            h = hashlib.sha256(t.encode("utf-8")).digest()
            buf = h
            while len(buf) < dim:
                buf += hashlib.sha256(buf).digest()
            vals = [b / 255.0 for b in buf[:dim]]
            # normalize
            norm = sum(v * v for v in vals) ** 0.5 + 1e-12
            out.append([v / norm for v in vals])
        return out

    def explain(self, prompt: str, max_tokens: int = 512, **kwargs) -> str:
        payload = {
            "explanation": "This is a mocked explanation for testing.",
            "fix": "Apply recommended best practices.",
            "references": ["http://example.com/mock"]
        }
        return json.dumps(payload)


def pytest_configure(config):
    # Inject FakeNIMClient into modules that import NIMClient so tests run offline.
    # Do NOT overwrite agent.nim_client.NIMClient (some tests assert parsing
    # behavior of the real client). Instead, inject the fake into higher-level
    # modules that instantiate NIM for online flows (llm_client, knowledge_store).
    try:
        import agent.llm_client as llm_mod
        llm_mod.NIMClient = FakeNIMClient
    except Exception:
        pass
    try:
        import agent.knowledge_store as ks_mod
        ks_mod.NIMClient = FakeNIMClient
    except Exception:
        pass
import os
import sys

# Ensure project root is on sys.path so tests can import
# `app` and `agent` packages.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
