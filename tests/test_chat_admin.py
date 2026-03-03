import os
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.app import app
from agent import persistence


def test_chat_sessions_lists_inmemory_and_persisted(tmp_path):
    client = TestClient(app)
    fake = {"explanation": "admin-list"}

    db_path = str(tmp_path / "sessions_admin.db")
    os.environ["CHAT_DB"] = db_path

    # create an in-memory session by posting
    with patch("agent.llm_client.LLMClient.explain", return_value=fake):
        r = client.post("/chat", json={"message": "One"})
        assert r.status_code == 200
        sid1 = r.json()["session_id"]

    # create another and then clear memory to simulate persisted-only
    with patch("agent.llm_client.LLMClient.explain", return_value=fake):
        r2 = client.post("/chat", json={"message": "Two"})
        sid2 = r2.json()["session_id"]

    # ensure both persisted
    assert persistence.load_session(sid1, path=db_path) is not None
    assert persistence.load_session(sid2, path=db_path) is not None

    # clear in-memory to make sid2 persisted-only
    from app import routes_chat
    routes_chat.SESSIONS.pop(sid2, None)

    # call admin endpoint
    res = client.get("/chat/sessions")
    assert res.status_code == 200
    j = res.json()
    sids = {s["session_id"] for s in j["sessions"]}
    assert sid1 in sids
    assert sid2 in sids
