"""Lightweight LLM client abstraction.

Supports two modes:
- offline: deterministic template-based explanations useful for local dev and tests
- nim (online): placeholder that attempts to call an external NVIDIA NIM inference client

The client exposes `explain(issue, context)` which returns a dict with keys: explanation, fix, references.
If online mode is not available it falls back to offline templates.
"""

from __future__ import annotations

import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("codeguardian.llm_client")


class LLMClient:
    def __init__(self, mode: Optional[str] = None):
        # mode: 'offline' or 'nim'
        self.mode = mode or os.environ.get("CODEGUARDIAN_LLM_MODE", "offline")
        # simple flag whether online inference is available
        self.online_available = False
        if self.mode == "nim":
            # try to import / initialize a real NIM client; if not present, fall back
            try:
                # Placeholder import — users can replace with real NIM SDK calls
                import nim  # type: ignore

                self.online_available = True
            except Exception:
                logger.warning(
                    "NIM client requested but not available; falling back to offline mode"
                )
                self.mode = "offline"

    def explain(self, issue: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Produce an explanation/fix/references for a single issue.

        issue: object from Stage 2 with keys like type, line, snippet, message
        context: optional additional context (file, surrounding code)
        """
        if self.mode == "nim" and self.online_available:
            try:
                return self._explain_online(issue, context)
            except Exception:
                logger.exception("Online LLM failed; falling back to offline templates")
                return self._explain_offline(issue, context)

        return self._explain_offline(issue, context)

    def _explain_online(self, issue: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Call the external NIM inference endpoint. This is a placeholder; projects should
        replace with actual SDK calls.
        """
        # Example stub — real implementation should build a rich prompt and parse JSON
        # response. Here we simply forward to offline behavior for safety.
        logger.debug("_explain_online would call NIM with issue=%s", issue.get("type"))
        return self._explain_offline(issue, context)

    def _explain_offline(self, issue: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Deterministic templated explanations for dev/test mode.

        This ensures tests can run without external models.
        """
        itype = (issue.get("type") or "Unknown").lower()
        snippet = issue.get("snippet") or ""

        # simple template mapping
        templates = {
            "hardcoded secret": {
                "explanation": "This file contains a hardcoded secret or credential in source code which can be read by anyone with repository access.",
                "fix": "Remove the secret from source control. Use environment variables, a .env file kept out of VCS, or a secret store (HashiCorp Vault, AWS Secrets Manager). Rotate the credential immediately if it was committed.",
                "references": ["https://owasp.org/www-project-top-ten/", "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
            },
            "possible sql injection": {
                "explanation": "This code constructs SQL statements by concatenating strings or by formatting them directly. Attackers can inject SQL fragments through inputs, leading to data leakage or corruption.",
                "fix": "Use parameterized queries (e.g., cursor.execute(sql, params)) or ORM query builders to avoid direct string composition of SQL. Validate and sanitize inputs.",
                "references": ["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
            },
            "insecure function usage": {
                "explanation": "Use of functions like eval() or exec() can execute arbitrary code and should be avoided, especially on user-controlled inputs.",
                "fix": "Replace eval/exec with safer alternatives. For parsing expressions use ast.literal_eval or write a simple parser. Validate inputs strictly.",
                "references": ["https://owasp.org/www-community/"],
            },
            "deprecated hash": {
                "explanation": "MD5 and SHA1 are considered cryptographically broken or weak for collision resistance and should not be used for security-sensitive hashing.",
                "fix": "Use hashlib.sha256 or a stronger function and use salt + PBKDF2 / bcrypt / scrypt / Argon2 for password hashing.",
                "references": ["https://owasp.org/www-project-top-ten/"],
            },
            "suspicious subprocess call": {
                "explanation": "Calling subprocess APIs with unsanitized inputs or with shell=True can allow command injection or execution of unintended commands.",
                "fix": "Avoid shell=True and pass arguments as a list. Validate and sanitize any inputs used in command construction.",
                "references": ["https://cheatsheetseries.owasp.org/"],
            },
            "insecure regex": {
                "explanation": "Overly-broad regex patterns like '.*' can match unintended input and can cause catastrophic backtracking.",
                "fix": "Use more specific regexes and apply input length limits. Consider non-greedy qualifiers and anchors as appropriate.",
                "references": ["https://owasp.org/www-community/"],
            },
        }

        choice = templates.get(itype, None)
        if choice:
            return {"explanation": choice["explanation"], "fix": choice["fix"], "references": choice["references"]}

        # default fallback
        return {
            "explanation": f"Detected issue of type '{issue.get('type')}'. {issue.get('message', '')}",
            "fix": "Investigate the finding and apply recommended best-practices (parameterization, secrets management, or safer library APIs).",
            "references": ["https://owasp.org/www-project-top-ten/"],
        }
