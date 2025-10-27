from fastapi.testclient import TestClient
from unittest.mock import patch

from app.app import app


def test_chat_endpoint_creates_session_and_replies(monkeypatch):
    client = TestClient(app)

    # mock LLMClient.explain to return a predictable response
    fake = {"explanation": "Hello, I am a mock LLM."}

    with patch("agent.llm_client.LLMClient.explain", return_value=fake) as mock_explain:
        r = client.post("/chat", json={"message": "Hi"})
        assert r.status_code == 200
        j = r.json()
        assert "session_id" in j
        assert j["reply"] == "Hello, I am a mock LLM."
        # ensure the LLM was called with an issue-like dict
        mock_explain.assert_called()


def test_chat_session_continues(monkeypatch):
    client = TestClient(app)
    fake1 = {"explanation": "First reply"}
    fake2 = {"explanation": "Second reply"}

    with patch("agent.llm_client.LLMClient.explain", side_effect=[fake1, fake2]) as mock_explain:
        r1 = client.post("/chat", json={"message": "Hello"})
        sid = r1.json()["session_id"]
        r2 = client.post("/chat", json={"session_id": sid, "message": "Again"})
        assert r2.status_code == 200
        assert r2.json()["reply"] == "Second reply"
        assert mock_explain.call_count == 2
