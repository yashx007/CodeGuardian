import os
import importlib

from fastapi.testclient import TestClient

from agent import persistence


def test_history_endpoints(tmp_path, monkeypatch):
    db = tmp_path / "reports.db"
    # point persistence to temp DB via env and reload module
    monkeypatch.setenv("CODEGUARDIAN_DB", str(db))
    importlib.reload(persistence)

    # ensure DB empty
    assert persistence.list_reports() == []

    # save a report
    rid = persistence.save_report("test.py", {"counts": {}, "risk": "Low"}, {"results": {}}, path=str(db))
    assert isinstance(rid, int)

    # reload app to ensure it uses updated persistence module (app imports persistence earlier)
    from app.app import app

    client = TestClient(app)

    r = client.get("/history")
    assert r.status_code == 200
    j = r.json()
    assert "reports" in j
    assert any(rep["filename"] == "test.py" or rep["filename"] == 'test.py' for rep in j["reports"]) or len(j["reports"]) >= 1

    # get the report by id
    r2 = client.get(f"/history/{rid}")
    assert r2.status_code == 200
    jr2 = r2.json()
    assert jr2.get("report") and jr2["report"]["id"] == rid
