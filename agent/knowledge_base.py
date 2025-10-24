"""Small in-memory knowledge base for Stage 3 reasoning.

Provides short factual entries and reference lists for common security issues.
In production this would be backed by embeddings + vector DB (FAISS/Chroma) and
an embedding service (NIM), but for development we keep a tiny offline KB.
"""

from __future__ import annotations

from typing import Dict, List


KB: Dict[str, Dict[str, object]] = {
    "hardcoded secret": {
        "summary": "Secrets such as API keys and passwords must not be stored in source code or committed to version control. Use secret managers and environment variables instead.",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            "https://owasp.org/www-project-top-ten/",
        ],
    },
    "possible sql injection": {
        "summary": "Unparameterized SQL or string-built queries can allow SQL injection attacks. Prefer parameterized queries or ORM APIs.",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://owasp.org/www-community/attacks/SQL_Injection"
        ],
    },
    "insecure function usage": {
        "summary": "Dynamic code execution functions (eval/exec) may execute attacker-controlled input. Use safer parsing libraries or restricted evaluators.",
        "references": ["https://owasp.org/www-community/"],
    },
    "deprecated hash": {
        "summary": "Weak hashing algorithms like MD5/SHA1 are unsuitable for security-sensitive purposes. Use SHA-2/3 or password-specific KDFs.",
        "references": ["https://www.ipa.go.jp/security/english/", "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"],
    },
    "suspicious subprocess call": {
        "summary": "Using subprocess APIs with shell=True or untrusted string inputs can lead to command injection. Pass args as a list and validate inputs.",
        "references": ["https://cheatsheetseries.owasp.org/"],
    },
    "insecure regex": {
        "summary": "Overly-broad regex patterns can cause catastrophic backtracking and unintended matches. Use anchors and limit quantifiers.",
        "references": ["https://owasp.org/www-community/"],
    },
}


class KnowledgeBase:
    def __init__(self, use_store: bool = False, store=None) -> None:
        """If `use_store` is True and a `store` (KnowledgeStore) is provided, the KB
        will delegate retrieval to that store. Otherwise it returns static entries.
        """
        self._kb = KB
        self._store = store
        self._use_store = use_store and store is not None

    def get(self, key: str) -> Dict[str, object]:
        return self._kb.get(key.lower(), {})

    def query(self, issue_type: str) -> Dict[str, object]:
        """Return a KB entry for the given issue type or an empty dict.

        If a KnowledgeStore is attached and use_store=True, perform retrieval for
        the issue type and include top matches in the returned dict under 'retrieved'.
        """
        base = self.get(issue_type)
        if not self._use_store:
            return base

        # query the external store for richer context
        try:
            hits = self._store.query(issue_type, top_k=3)
            base = dict(base)  # shallow copy
            base["retrieved"] = [
                {"id": h[0], "score": h[1], "text": h[2]} for h in hits
            ]
            return base
        except Exception:
            return base
