import io

from fastapi.testclient import TestClient

from app.app import app


client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_scan_hardcoded_secret():
    code = "api_key = \"API_KEY=abcd1234\"\n"
    files = {
        "file": (
            "secrets.py",
            io.BytesIO(code.encode("utf-8")),
            "text/plain",
        )
    }
    r = client.post("/scan", files=files)
    assert r.status_code == 200
    j = r.json()
    assert "Hardcoded secret" in j["issue"]
