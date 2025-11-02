import json
import os

import pytest

import agent.aws_client as aws_mod


class _FakeBody:
    def __init__(self, b: bytes):
        self._b = b

    def read(self):
        return self._b


class _FakeClient:
    def __init__(self, responses: dict):
        # responses: mapping of endpoint name -> bytes to return
        self.responses = responses

    def invoke_endpoint(self, EndpointName=None, ContentType=None, Body=None):
        data = self.responses.get(EndpointName)
        if isinstance(data, Exception):
            raise data
        return {"Body": _FakeBody(data)}


def test_explain_parsing_batch(monkeypatch):
    # prepare fake responses for LLM and embedding endpoints
    llm_text = json.dumps(
        {"explanation": "ok", "fix": "do X", "references": ["http://a"]}
    ).encode("utf-8")
    emb_data = json.dumps(
        {"data": [{"embedding": [0.1, 0.2]}, {"embedding": [0.2, 0.3]}]}
    ).encode("utf-8")

    def fake_client_factory(service, region_name=None):
        return _FakeClient({"llm-endpoint": llm_text, "emb-endpoint": emb_data})

    monkeypatch.setattr(
        aws_mod, "boto3", type("m", (), {"client": fake_client_factory})
    )

    # set env vars expected by SageMakerClient
    monkeypatch.setenv("SAGEMAKER_LLM_ENDPOINT", "llm-endpoint")
    monkeypatch.setenv("SAGEMAKER_EMBEDDING_ENDPOINT", "emb-endpoint")

    client = aws_mod.SageMakerClient(region="us-west-2")
    out = client.explain("hello world")
    # explain returns raw text (JSON string); ensure it's the expected JSON
    parsed = json.loads(out)
    assert parsed["explanation"] == "ok"

    embs = client.embed(["a", "b"])  # expects list of 2 vectors
    assert isinstance(embs, list)
    assert len(embs) == 2
    assert embs[0] == [0.1, 0.2]


def test_embed_per_text_fallback(monkeypatch):
    # Simulate batch call failing (raise) and per-text calls returning simple JSON
    def fake_client_factory(service, region_name=None):
        # this fake will return an Exception for batch endpoint and valid per-text for single
        class C:
            def invoke_endpoint(self, EndpointName=None, ContentType=None, Body=None):
                # if Body is JSON array (batch), simulate failure
                try:
                    parsed = json.loads(Body)
                    # if parsed looks like a list of texts or dict with list, error
                    if isinstance(parsed, dict) and any(
                        isinstance(v, list) for v in parsed.values()
                    ):
                        raise RuntimeError("batch failure")
                except Exception:
                    pass
                # return per-text embedding JSON
                resp = json.dumps({"embedding": [0.5, 0.6]}).encode("utf-8")
                return {"Body": _FakeBody(resp)}

        return C()

    monkeypatch.setattr(
        aws_mod, "boto3", type("m", (), {"client": fake_client_factory})
    )
    monkeypatch.setenv("SAGEMAKER_EMBEDDING_ENDPOINT", "emb-endpoint")

    client = aws_mod.SageMakerClient(region="us-west-2")
    embs = client.embed(["only one text"])
    assert isinstance(embs, list)
    assert len(embs) == 1
    assert embs[0] == [0.5, 0.6]
