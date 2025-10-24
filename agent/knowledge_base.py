"""Small in-memory knowledge base for Stage 3 reasoning.

Provides short factual entries and reference lists for common security issues.
In production this would be backed by embeddings + vector DB (FAISS/Chroma) and
an embedding service (NIM), but for development we keep a tiny offline KB.
"""

from __future__ import annotations

from typing import Dict, List


KB: Dict[str, Dict[str, object]] = {
    "hardcoded secret": {
        "summary": "Secrets such as API keys and passwords must not be stored in source code or committed to version control.",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            "https://owasp.org/Top10/",
        ],
    },
    "possible sql injection": {
        "summary": "Unparameterized SQL or string-built queries can allow SQL injection attacks.",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ],
    },
    "insecure function usage": {
        "summary": "Dynamic code execution functions (eval/exec) may execute attacker-controlled input.",
        "references": ["https://owasp.org/www-community/"],
    },
    "deprecated hash": {
        "summary": "Weak hashing algorithms like MD5/SHA1 are unsuitable for security-sensitive purposes.",
        "references": ["https://www.ipa.go.jp/security/english/"],
    },
}


class KnowledgeBase:
    def __init__(self) -> None:
        self._kb = KB

    def get(self, key: str) -> Dict[str, object]:
        return self._kb.get(key.lower(), {})

    def query(self, issue_type: str) -> Dict[str, object]:
        """Return a KB entry for the given issue type or an empty dict."""
        return self.get(issue_type)
