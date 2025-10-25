import pytest

from agent.reasoning import Reasoner


def test_reasoner_enrich_with_mocked_llm():
    # Prepare a simple finding with types that map to severities
    findings = [
        {"file": "input/test_insecure.py", "type": "Hardcoded Secret", "line": 7, "snippet": "password = 'hunter2'", "message": "Hardcoded credential"},
        {"file": "input/test_insecure.py", "type": "Deprecated Hash", "line": 26, "snippet": "hashlib.md5(b'data')", "message": "Use of MD5"},
    ]

    r = Reasoner(llm_mode="offline")

    # Monkeypatch the LLM explain to return deterministic content regardless of input
    def fake_explain(issue, context=None):
        itype = (issue.get("type") or "").lower()
        if "secret" in itype:
            return {
                "explanation": "Credentials are hardcoded in source code.",
                "fix": "Move the secret to environment variables.",
                "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
            }
        if "deprecated" in itype or "md5" in (issue.get("snippet") or "").lower():
            return {
                "explanation": "MD5 is weak and should not be used for security-sensitive hashing.",
                "fix": "Use hashlib.sha256 or a password KDF like bcrypt/argon2.",
                "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"],
            }
        return {"explanation": "Generic explanation.", "fix": "Generic fix.", "references": []}

    # attach fake explain
    r.llm.explain = fake_explain

    out = r.enrich(findings)

    assert "results" in out and "summary" in out
    results = out["results"]
    assert "input/test_insecure.py" in results

    issues = results["input/test_insecure.py"]
    assert len(issues) == 2

    # check that severity mapping applied
    secret_issue = next((i for i in issues if "secret" in (i.get("type") or "").lower()), None)
    assert secret_issue is not None
    assert secret_issue.get("severity") == "High"
    assert "explanation" in secret_issue and secret_issue["explanation"].startswith("Credentials")

    # check deprecated hash mapped to Medium
    dep = next((i for i in issues if "deprecated" in (i.get("type") or "").lower() or "md5" in (i.get("snippet") or "")), None)
    assert dep is not None
    assert dep.get("severity") == "Medium"
    assert "MD5" in dep.get("explanation") or "md5" in dep.get("snippet").lower()

    # summary risk heuristic: High due to the secret
    summary = out["summary"]
    assert summary["risk"] == "High"
    assert summary["total_issues"] == 2
