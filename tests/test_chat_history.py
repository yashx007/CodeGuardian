from fastapi.testclient import TestClient
from unittest.mock import patch
from datetime import datetime, timezone, timedelta
import os

from app.app import app
import app.routes_chat as routes_chat


def test_chat_history_returns_messages():
    client = TestClient(app)
    fake = {"explanation": "History reply"}

    with patch("agent.llm_client.LLMClient.explain", return_value=fake):
        r = client.post("/chat", json={"message": "Hello history"})
        assert r.status_code == 200
        sid = r.json()["session_id"]

        # fetch history
        hr = client.get(f"/chat/{sid}/history")
        assert hr.status_code == 200
        data = hr.json()
        assert data["session_id"] == sid
        # expect at least user and assistant messages
        assert len(data["messages"]) >= 2


def test_chat_history_expiry():
    client = TestClient(app)
    fake = {"explanation": "Will expire"}

    with patch("agent.llm_client.LLMClient.explain", return_value=fake):
        r = client.post("/chat", json={"message": "Temp"})
        sid = r.json()["session_id"]

        # force session to appear old
        old = (datetime.now(timezone.utc) - timedelta(seconds=3600)).isoformat()
        routes_chat.SESSIONS[sid]["last_active"] = old

        # set TTL to 1 second so expiry check will remove it
        os.environ["CHAT_SESSION_TTL_SECONDS"] = "1"

        hr = client.get(f"/chat/{sid}/history")
        assert hr.status_code == 404
