import pytest

from agent.engine import AgentEngine


def test_detects_hardcoded_secret():
    engine = AgentEngine()
    content = 'api_key = "API_KEY=abcd1234"\n'
    res = engine.scan_code("secrets.py", content)
    assert isinstance(res, dict)
    assert "API key" in res["issue"] or "secret" in res["issue"].lower() or "Hardcoded" in res["issue"]
    assert "secret" in res["suggestion"].lower() or "environment" in res["suggestion"].lower()


def test_detects_sql_concatenation():
    engine = AgentEngine()
    content = 'query = "SELECT * FROM users WHERE id = " + user_id\n'
    res = engine.scan_code("db.py", content)
    assert (
        "SQL" in res["issue"]
        or "SQL" in res["suggestion"].upper()
        or "sql" in res["suggestion"].lower()
    )


def test_no_issue():
    engine = AgentEngine()
    content = "def add(a, b):\n    return a + b\n"
    res = engine.scan_code("util.py", content)
    assert res["issue"] == "No obvious issues found"
