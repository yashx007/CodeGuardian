"""Mock retrieval client to simulate security knowledge lookup."""

from typing import Dict


class RetrievalClient:
    def __init__(self):
        # comprehensive in-memory knowledge base
        self.kb: Dict[str, str] = {
            "hardcoded secret": (
                "Avoid storing secrets in code. Use environment variables or "
                "secret managers (HashiCorp Vault, AWS Secrets Manager). "
                "Rotate any credential that was committed."
            ),
            "sql injection": (
                "Use parameterized queries or ORM query builders to avoid "
                "SQL injection. Never concatenate user input into SQL strings."
            ),
            "insecure function": (
                "Avoid eval(), exec(), and similar dynamic code execution. "
                "Use ast.literal_eval() or a safe parser instead."
            ),
            "insecure deserialization": (
                "Do not deserialize untrusted data with pickle, marshal, or "
                "yaml.load(). Use JSON or yaml.safe_load() instead."
            ),
            "command injection": (
                "Avoid shell=True and os.system(). Pass arguments as a list "
                "to subprocess, and validate/sanitize all user inputs."
            ),
            "deprecated hash": (
                "MD5 and SHA-1 are cryptographically broken. Use SHA-256+ for "
                "integrity and bcrypt/scrypt/argon2 for password hashing."
            ),
            "insecure regex": (
                "Overly broad regex patterns (e.g. '.*') can cause ReDoS or "
                "match unintended input. Use anchors, bounds, and atomic groups."
            ),
            "insecure tls": (
                "Never set verify=False in production. This disables TLS "
                "certificate verification and exposes traffic to MITM attacks."
            ),
            "xss": (
                "Escape or sanitize all user-supplied content before inserting "
                "into the DOM. Use textContent instead of innerHTML, and "
                "libraries like DOMPurify."
            ),
            "path traversal": (
                "Validate and canonicalize file paths. Reject inputs containing "
                "'..'. Use os.path.realpath() and check against an allowed base."
            ),
        }

    def lookup(self, query: str) -> str:
        q = query.lower()
        for key, value in self.kb.items():
            if key in q or q in key:
                return value
        return "Review the finding and apply security best practices."
