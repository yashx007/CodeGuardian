import os
import json
import types

from agent.aws_client import SageMakerClient


class FakeBody:
    def __init__(self, b: bytes):
        self._b = b

    def read(self):
        return self._b


class FakeBoto:
    def __init__(self, llm_resp: bytes, emb_resp: bytes):
        self.llm_resp = llm_resp
        self.emb_resp = emb_resp

    def invoke_endpoint(self, EndpointName=None, ContentType=None, Body=None):
        if EndpointName == "llm":
            return {"Body": FakeBody(self.llm_resp)}
        if EndpointName == "emb":
            return {"Body": FakeBody(self.emb_resp)}
        return {"Body": FakeBody(b'')}


def test_sagemaker_client_explain_and_embed(monkeypatch):
    # Ensure environment points to our fake endpoints
    monkeypatch.setenv("SAGEMAKER_LLM_ENDPOINT", "llm")
    monkeypatch.setenv("SAGEMAKER_EMBEDDING_ENDPOINT", "emb")

    # Prepare fake responses
    llm_json = json.dumps({"explanation": "explain me", "fix": "do this", "references": []})
    emb_json = json.dumps({"data": [{"embedding": [0.1, 0.2, 0.3]}]})

    fake = FakeBoto(llm_resp=llm_json.encode("utf-8"), emb_resp=emb_json.encode("utf-8"))

    # Monkeypatch the boto3 client factory used by the module
    import agent.aws_client as aws_mod

    monkeypatch.setattr(aws_mod, "boto3", types.SimpleNamespace(client=lambda *a, **k: fake))

    client = SageMakerClient(region="us-east-1")

    out = client.explain("hello world")
    # explain should return textual JSON (raw from endpoint)
    assert isinstance(out, str)
    parsed = json.loads(out)
    assert parsed.get("explanation") == "explain me"

    embs = client.embed(["a"])
    assert isinstance(embs, list)
    assert len(embs) == 1
    assert all(isinstance(x, float) for x in embs[0])
