"""Wrapper for NVIDIA NIM inference and embedding endpoints.

This module provides a thin abstraction over NIM endpoints. It reads
configuration from environment variables:
- NIM_INFERENCE_URL: URL to call for text completion/reasoning
- NIM_EMBEDDING_URL: URL to call for embeddings
- NIM_API_KEY: optional API key for auth

The implementation uses `requests` to POST JSON payloads. This keeps the
dependency surface minimal; projects can replace with the official NIM SDK.

All methods are defensive: if requests/endpoint is not available it raises
RuntimeError and callers should fall back to offline logic.
"""

from __future__ import annotations

import os
import logging
from typing import List, Optional

logger = logging.getLogger("codeguardian.nim_client")

try:
    import requests
except Exception:
    requests = None  # type: ignore


class NIMClient:
    def __init__(self, inference_url: Optional[str] = None, embedding_url: Optional[str] = None, api_key: Optional[str] = None):
        # Support either explicit URLs or model-based construction using NIM_BASE_URL
        self.inference_url = inference_url or os.environ.get("NIM_INFERENCE_URL")
        self.embedding_url = embedding_url or os.environ.get("NIM_EMBEDDING_URL")
        self.base_url = os.environ.get("NIM_BASE_URL")
        # model names (defaults)
        # default inference model updated to the requested llama-3.1-nemotron-nano-8b-v1
        self.inference_model = os.environ.get("NIM_INFERENCE_MODEL", "llama-3.1-nemotron-nano-8b-v1")
        self.embedding_model = os.environ.get("NIM_EMBEDDING_MODEL", "nv-embedcode-7b-v1")

        # If explicit embedding_url not provided but base_url+model available, construct a default path
        if self.base_url:
            # If the base looks like the NVIDIA Integrate v1 host, prefer the v1 endpoints
            base = self.base_url.rstrip('/')
            if "integrate.api.nvidia.com" in base or base.endswith('/v1'):
                # integrate-style base (we'll construct v1 endpoints)
                # ensure we don't duplicate /v1
                v1_base = base.rstrip('/')
                if not v1_base.endswith('/v1'):
                    v1_base = v1_base + '/v1'
                if not self.embedding_url:
                    # integrate v1 embeddings endpoint
                    self.embedding_url = f"{v1_base}/embeddings"
                if not self.inference_url:
                    # integrate v1 chat/completions endpoint
                    self.inference_url = f"{v1_base}/chat/completions"
            else:
                # default model-based patterns
                if not self.embedding_url and self.embedding_model:
                    self.embedding_url = f"{base}/models/{self.embedding_model}/embeddings"
                if not self.inference_url and self.inference_model:
                    self.inference_url = f"{base}/models/{self.inference_model}/infer"
        # support per-model API keys if provided; fall back to NIM_API_KEY
        self.api_key = api_key or os.environ.get("NIM_API_KEY")
        self.embedding_api_key = os.environ.get("NIM_API_KEY_EMBEDDING") or self.api_key
        self.inference_api_key = os.environ.get("NIM_API_KEY_INFERENCE") or self.api_key

        if not requests:
            logger.warning("requests not installed; NIM client disabled")

    def _headers(self, api_key: Optional[str] = None):
        h = {"Content-Type": "application/json"}
        key = api_key or self.api_key
        if key:
            h["Authorization"] = f"Bearer {key}"
        return h

    def explain(self, prompt: str, max_tokens: int = 512, **kwargs) -> str:
        """Call the NIM inference endpoint with a simple prompt and return text.

        Expected JSON shape depends on deployment; this function sends a small
        generic payload and expects a JSON response with a `text` or `output` field.
        Replace with your deployment's schema as needed.
        """
        if not requests or not self.inference_url:
            raise RuntimeError("NIM inference unavailable")

        # If the inference_url looks like the integrate v1 chat endpoint, send a chat/completions payload
        try:
            if self.inference_url and "chat/completions" in self.inference_url:
                messages = kwargs.pop('messages', None)
                if messages is None:
                    messages = [{"role": "user", "content": prompt}]
                payload = {"model": self.inference_model, "messages": messages, "max_tokens": max_tokens, **kwargs}
                r = requests.post(self.inference_url, json=payload, headers=self._headers(self.inference_api_key), timeout=15)
                r.raise_for_status()
                data = r.json()
                # Integrate v1 returns choices with message.content
                if isinstance(data, dict) and "choices" in data and isinstance(data["choices"], list) and data["choices"]:
                    first = data["choices"][0]
                    # choice may be {'message': {'content': '...'}} or {'text': '...'}
                    if isinstance(first, dict):
                        if "message" in first and isinstance(first["message"], dict) and "content" in first["message"]:
                            return first["message"]["content"]
                        if "text" in first:
                            return first["text"]
                # fallback to other fields
                if "text" in data:
                    return data["text"]
                if "output" in data:
                    return data["output"]
                return str(data)
            else:
                # legacy model infer endpoint (prompt-based)
                payload = {"prompt": prompt, "max_tokens": max_tokens, **kwargs}
                r = requests.post(self.inference_url, json=payload, headers=self._headers(self.inference_api_key), timeout=10)
                r.raise_for_status()
                data = r.json()
                if "text" in data:
                    return data["text"]
                if "output" in data:
                    return data["output"]
                if "choices" in data and isinstance(data["choices"], list) and data["choices"]:
                    first = data["choices"][0]
                    if isinstance(first, dict) and "text" in first:
                        return first["text"]
                return str(data)
        except Exception as e:
            logger.exception("NIM inference call failed: %s", e)
            raise

    def embed(self, texts: List[str]) -> List[List[float]]:
        """Call the NIM embedding endpoint to get vectors for a list of texts.

        Expected response: {"embeddings": [[...], [...]]}
        """
        if not requests or not self.embedding_url:
            raise RuntimeError("NIM embedding unavailable")

        # Try NVIDIA Integrate v1 style first (model + input + input_type)
        integrate_payload = {
            "model": self.embedding_model,
            "input": texts,
            # many integrate models expect 'query' or 'passage' for input_type
            "input_type": "query",
            "encoding_format": "float",
            "truncate": "NONE",
        }

        legacy_payload = {"texts": texts}

        # helper to parse common response shapes
        def _parse_embedding_response(data):
            if not isinstance(data, dict):
                return None
            # common 'embeddings' key
            if "embeddings" in data and isinstance(data["embeddings"], list):
                return data["embeddings"]
            # integrate v1 style: {"object":"list","data":[{"embedding": [...]}]}
            if "data" in data and isinstance(data["data"], list):
                emb = []
                for it in data["data"]:
                    if isinstance(it, dict) and "embedding" in it:
                        emb.append(it["embedding"])
                if emb:
                    return emb
            return None

        # Try integrate-style request first
        try:
            r = requests.post(self.embedding_url, json=integrate_payload, headers=self._headers(self.embedding_api_key), timeout=15)
            # allow server to respond with status to indicate missing fields
            r.raise_for_status()
            data = r.json()
            parsed = _parse_embedding_response(data)
            if parsed is not None:
                return parsed
        except Exception:
            # don't bail out yet — we'll try legacy shape next
            logger.debug("Integrate-style embedding request failed; will try legacy payload", exc_info=True)

        # Fallback: try legacy payload shape commonly used by other deployments
        try:
            r = requests.post(self.embedding_url, json=legacy_payload, headers=self._headers(self.embedding_api_key), timeout=15)
            r.raise_for_status()
            data = r.json()
            parsed = _parse_embedding_response(data)
            if parsed is not None:
                return parsed
            raise RuntimeError("Unexpected embedding response format")
        except Exception:
            logger.exception("Failed to get embeddings from NIM (both integrate and legacy payloads attempted)")
            raise
