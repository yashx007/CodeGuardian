import os
from pathlib import Path

from agent import parser
from agent.reasoning import Reasoner


def test_reasoning_end2end_with_mocks(tmp_path, monkeypatch):
    # Ensure we run in 'nim' mode so LLMClient uses the FakeNIMClient injected by conftest
    os.environ["CODEGUARDIAN_LLM_MODE"] = "nim"

    # analyze a known sample file in the input/ directory
    sample = Path(__file__).parent.parent / "input" / "test_insecure.py"
    assert sample.exists(), "sample input file missing"

    issues = parser.analyze_code(str(sample))
    assert isinstance(issues, list) and len(issues) > 0

    r = Reasoner(llm_mode="nim")
    out = r.enrich({str(sample): issues})

    # basic assertions about structure
    assert "results" in out and "summary" in out
    results = out["results"]
    assert str(sample) in results

    enriched = results[str(sample)]
    assert isinstance(enriched, list) and len(enriched) == len(issues)

    # Because FakeNIMClient returns a deterministic mocked explanation, check presence
    for it in enriched:
        assert "explanation" in it and it["explanation"].startswith("This is a mocked explanation")
        assert "fix" in it
        assert "severity" in it

    # summary should reflect total issues
    assert out["summary"]["total_issues"] == len(issues)
