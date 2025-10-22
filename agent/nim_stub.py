"""Mock retrieval client to simulate security knowledge lookup."""

from typing import Dict


class RetrievalClient:
    def __init__(self):
        # small in-memory knowledge base
        self.kb: Dict[str, str] = {
            "hardcoded secret": "Avoid storing secrets in code. Use environment variables or secret managers.",
            "sql injection": "Use parameterized queries or ORM query builders to avoid SQL injection.",
        }

    def lookup(self, query: str) -> str:
        return self.kb.get(query, "No relevant guidance found")
