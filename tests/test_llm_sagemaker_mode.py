import json
from unittest.mock import MagicMock

from agent.llm_client import LLMClient


def test_llmclient_sagemaker_parses_json(monkeypatch):
    # Fake SageMaker client with explain returning JSON string
    fake_sm = MagicMock()
    fake_sm.explain.return_value = json.dumps(
        {
            "explanation": "ex",
            "fix": "do it",
            "references": ["http://x"],
        }
    )

    # Patch SageMakerClient used by LLMClient
    monkeypatch.setattr(
        "agent.llm_client.SageMakerClient", lambda *args, **kwargs: fake_sm
    )

    client = LLMClient(mode="sagemaker")
    res = client.explain(
        {
            "type": "hardcoded secret",
            "line": 1,
            "snippet": "pw='x'",
            "message": "secret",
        },
        context={},
    )
    assert res["explanation"] == "ex"
    assert res["fix"] == "do it"
    assert isinstance(res["references"], list)


def test_llmclient_sagemaker_parses_text_fallback(monkeypatch):
    fake_sm = MagicMock()
    # Return plain text with Fix: marker and a http ref
    fake_sm.explain.return_value = "Impact: X\nFix: change to safe API\nhttp://ref"

    monkeypatch.setattr(
        "agent.llm_client.SageMakerClient", lambda *args, **kwargs: fake_sm
    )

    client = LLMClient(mode="sagemaker")
    res = client.explain(
        {
            "type": "insecure function",
            "line": 5,
            "snippet": "eval(x)",
            "message": "use of eval",
        },
        context={},
    )
    assert "Fix" in res["fix"] or "fix" in res["fix"].lower()
    assert (
        any(r.startswith("http") for r in res["references"]) or res["references"] == []
    )
