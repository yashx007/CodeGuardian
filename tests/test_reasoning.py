import os

from agent import parser
from agent.reasoning import Reasoner


def test_reasoner_offline_enrich():
    # Ensure offline mode (deterministic) for testing
    os.environ.pop("CODEGUARDIAN_LLM_MODE", None)
    r = Reasoner(llm_mode="offline")

    path = os.path.join(os.path.dirname(__file__), "..", "input", "test_insecure.py")
    # normalize path
    path = os.path.normpath(path)

    issues = parser.analyze_code(path)
    assert isinstance(issues, list)
    enriched = r.enrich({path: issues})

    assert "results" in enriched
    assert "summary" in enriched
    # each issue should have explanation, fix, severity
    for fp, items in enriched["results"].items():
        for it in items:
            assert "explanation" in it
            assert "fix" in it
            assert "severity" in it
