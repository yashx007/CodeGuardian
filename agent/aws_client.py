"""Simple SageMaker Runtime client wrapper for LLM and embedding endpoints.

This wrapper uses boto3.sagemaker-runtime to invoke deployed SageMaker endpoints.
It is intentionally forgiving about payload shapes because different NIM->SageMaker
deployments may expect slightly different JSON schemas. The wrapper tries a
few reasonable payload shapes and returns the model's raw text or parsed JSON.

Environment variables used:
- SAGEMAKER_LLM_ENDPOINT: name of SageMaker endpoint for LLM inference
- SAGEMAKER_EMBEDDING_ENDPOINT: name of SageMaker endpoint for embeddings
- AWS_REGION: optional, used to construct boto3 client
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

try:
    import boto3
except Exception:
    boto3 = None  # type: ignore

logger = logging.getLogger("codeguardian.aws_client")


class SageMakerClient:
    def __init__(self, region: Optional[str] = None):
        if boto3 is None:
            raise RuntimeError("boto3 is required for SageMakerClient")
        self.region = region or os.environ.get("AWS_REGION") or None
        self.client = boto3.client("sagemaker-runtime", region_name=self.region)
        self.llm_endpoint = os.environ.get("SAGEMAKER_LLM_ENDPOINT")
        self.embedding_endpoint = os.environ.get("SAGEMAKER_EMBEDDING_ENDPOINT")

    def _invoke(self, endpoint_name: str, payload: Any, content_type: str = "application/json") -> str:
        try:
            body = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
            resp = self.client.invoke_endpoint(EndpointName=endpoint_name, ContentType=content_type, Body=body)
            # Body is a StreamingBody
            b = resp["Body"].read()
            text = b.decode("utf-8")
            return text
        except Exception as e:
            logger.exception("SageMaker invoke failed: %s", e)
            raise

    def explain(self, prompt: str, max_tokens: int = 512) -> str:
        """Invoke LLM endpoint with a prompt and return raw text output.

        We try a couple payload shapes: {"inputs": prompt} and {"text": prompt}.
        """
        if not self.llm_endpoint:
            raise RuntimeError("SAGEMAKER_LLM_ENDPOINT not configured")

        # Try preferred shape
        for payload in ({"inputs": prompt, "max_tokens": max_tokens}, {"text": prompt}):
            try:
                out = self._invoke(self.llm_endpoint, payload)
                return out
            except Exception:
                continue

        # last attempt: raw prompt
        return self._invoke(self.llm_endpoint, prompt)

    def embed(self, texts: List[str]) -> List[List[float]]:
        """Invoke embedding endpoint. Many deployments accept batch inputs.

        If batch call fails, fall back to per-text calls.
        Returns: list of vectors (floats)
        """
        if not self.embedding_endpoint:
            raise RuntimeError("SAGEMAKER_EMBEDDING_ENDPOINT not configured")

        # try batch payload
        candidates = [
            {"inputs": texts},
            {"input": texts},
            {"texts": texts},
        ]
        for p in candidates:
            try:
                out = self._invoke(self.embedding_endpoint, p)
                # parse: try JSON with top-level 'data' or direct list
                try:
                    parsed = json.loads(out)
                    # common shapes: {'data': [{'embedding': [...]}, ...]} or {'embeddings': [...]} or list
                    if isinstance(parsed, dict) and parsed.get("data"):
                        embs = []
                        for d in parsed.get("data", []):
                            if isinstance(d, dict) and d.get("embedding"):
                                embs.append(d.get("embedding"))
                        if embs:
                            return embs
                    if isinstance(parsed, dict) and parsed.get("embeddings"):
                        return parsed.get("embeddings")
                    if isinstance(parsed, list) and parsed and isinstance(parsed[0], list):
                        return parsed
                except Exception:
                    # not JSON or unexpected shape — continue
                    pass
            except Exception:
                continue

        # fallback: per-text call
        vectors: List[List[float]] = []
        for t in texts:
            try:
                out = self._invoke(self.embedding_endpoint, {"input": t})
                try:
                    parsed = json.loads(out)
                    if isinstance(parsed, dict) and parsed.get("embedding"):
                        vectors.append(parsed.get("embedding"))
                        continue
                    if isinstance(parsed, list) and parsed and isinstance(parsed[0], (int, float)):
                        vectors.append(parsed)
                        continue
                except Exception:
                    # if not JSON, try to parse simple whitespace/comma-separated floats
                    parts = out.strip().replace(",", " ").split()
                    try:
                        fv = [float(x) for x in parts if x]
                        if fv:
                            vectors.append(fv)
                            continue
                    except Exception:
                        pass
                # if all else fails, raise
                raise RuntimeError("Unrecognized embedding response")
            except Exception:
                logger.exception("Failed to get embedding for text: %s", t)
                vectors.append([])

        return vectors
