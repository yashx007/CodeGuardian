"""Simple agent engine that orchestrates scanning."""

from typing import Dict

from .nim_stub import RetrievalClient


class AgentEngine:
    def __init__(self):
        self.retriever = RetrievalClient()

    def scan_code(self, filename: str, content: str) -> Dict[str, str]:
        """Run a very small pipeline: pattern checks + retrieval hints.

        Returns a dictionary with 'issue' and 'suggestion'.
        """
        # naive pattern checks
        if "API_KEY" in content or "aws_access_key_id" in content:
            hint = self.retriever.lookup("hardcoded secret")
            return {
                "issue": "Hardcoded secret detected",
                "suggestion": hint,
            }

        if "SELECT" in content and "+" in content:
            hint = self.retriever.lookup("sql injection")
            return {
                "issue": "Possible SQL concatenation",
                "suggestion": hint,
            }

        return {
            "issue": "No obvious issues found",
            "suggestion": "No action required",
        }


engine = AgentEngine()
