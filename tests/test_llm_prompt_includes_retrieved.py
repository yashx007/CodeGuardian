from unittest.mock import MagicMock
from agent.llm_client import LLMClient


def test_online_prompt_includes_retrieved(monkeypatch):
    # Create a client in nim mode but inject a fake nim client
    client = LLMClient(mode="nim")
    fake_nim = MagicMock()

    # fake explain returns a JSON string
    fake_nim.explain.return_value = '{"explanation": "ok", "fix": "fix it", "references": ["http://example.com"]}'
    client.nim = fake_nim
    client.online_available = True

    issue = {"type": "hardcoded secret", "line": 10, "snippet": "password = 'hunter2'", "message": "Found password"}
    context = {
        "file": "input/test_insecure.py",
        "kb": {
            "summary": "Secrets must not be committed.",
            "retrieved": [{"id": "hardcoded secret", "score": 0.9, "text": "Use environment variables and secret managers."}]
        }
    }

    res = client._explain_online(issue, context)
    # ensure nim.explain was called with a prompt that includes retrieved text
    called_args = fake_nim.explain.call_args[0][0]
    assert "Use environment variables and secret managers." in called_args
    assert res["explanation"] == "ok"
    assert res["fix"] == "fix it"
