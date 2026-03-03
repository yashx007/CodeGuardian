import os
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.app import app
import app.routes_chat as routes_chat
from agent import persistence


def test_chat_delete_endpoint_removes_session(tmp_path):
    client = TestClient(app)
    fake = {"explanation": "To be deleted"}

    db_path = str(tmp_path / "sessions_del.db")
    os.environ["CHAT_DB"] = db_path

    with patch("agent.llm_client.LLMClient.explain", return_value=fake):
        r = client.post("/chat", json={"message": "Delete me"})
        assert r.status_code == 200
        sid = r.json()["session_id"]

    # ensure persisted
    assert persistence.load_session(sid, path=db_path) is not None

    # delete via endpoint
    d = client.delete(f"/chat/{sid}")
    assert d.status_code in (200, 204)

    # should be removed from persistence
    assert persistence.load_session(sid, path=db_path) is None


def test_evict_expired_once_removes_persisted(tmp_path):
    client = TestClient(app)
    fake = {"explanation": "Evict me"}

    db_path = str(tmp_path / "sessions_evict.db")
    os.environ["CHAT_DB"] = db_path

    with patch("agent.llm_client.LLMClient.explain", return_value=fake):
        r = client.post("/chat", json={"message": "Temp"})
        sid = r.json()["session_id"]

    # force last_active to a long time ago in persistence
    old = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    # load messages to re-save with old timestamp
    loaded = persistence.load_session(sid, path=db_path)
    assert loaded is not None
    persistence.save_session(sid, loaded["messages"], old, path=db_path)

    # call eviction pass
    removed = routes_chat.evict_expired_once()
    assert removed >= 1

    # ensure persistence gone
    assert persistence.load_session(sid, path=db_path) is None
