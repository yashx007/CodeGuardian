import os
import json
import tempfile
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.app import app
import app.routes_chat as routes_chat
from agent import persistence


def test_chat_persistence_survives_restart(tmp_path):
    client = TestClient(app)
    fake = {"explanation": "Persisted reply"}

    # use a temp DB for chat persistence
    db_path = str(tmp_path / "sessions_test.db")
    os.environ["CHAT_DB"] = db_path

    with patch("agent.llm_client.LLMClient.explain", return_value=fake):
        r = client.post("/chat", json={"message": "Persistent"})
        assert r.status_code == 200
        sid = r.json()["session_id"]

    # ensure persistence saved
    loaded = persistence.load_session(sid, path=db_path)
    assert loaded is not None
    assert len(loaded["messages"]) >= 2

    # simulate restart by clearing in-memory sessions
    routes_chat.SESSIONS.clear()

    # fetch history, should load from DB
    hr = client.get(f"/chat/{sid}/history")
    assert hr.status_code == 200
    data = hr.json()
    assert data["session_id"] == sid
    assert len(data["messages"]) >= 2
