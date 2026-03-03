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

try:
    from .nim_client import NIMClient
except Exception:
    NIMClient = None  # type: ignore
try:
    from .aws_client import SageMakerClient
except Exception:
    SageMakerClient = None  # type: ignore

logger = logging.getLogger("codeguardian.llm_client")


class LLMClient:
    def __init__(self, mode: Optional[str] = None):
        # mode: 'offline' or 'nim'
        self.mode = mode or os.environ.get("CODEGUARDIAN_LLM_MODE", "offline")
        self.online_available = False
        self.nim = None
        self.sagemaker = None

        if self.mode == "nim" and NIMClient is not None:
            try:
                self.nim = NIMClient()
                if getattr(self.nim, "inference_url", None) or getattr(
                    self.nim, "embedding_url", None
                ):
                    self.online_available = True
            except Exception:
                logger.warning(
                    "Failed to initialize NIM client; falling back to offline"
                )
                self.mode = "offline"

        if self.mode == "sagemaker" and SageMakerClient is not None:
            try:
                self.sagemaker = SageMakerClient()
                # available if endpoint env var present
                if getattr(self.sagemaker, "llm_endpoint", None) or getattr(
                    self.sagemaker, "embedding_endpoint", None
                ):
                    self.online_available = True
            except Exception:
                logger.warning(
                    "Failed to initialize SageMaker client; falling back to offline"
                )
                self.mode = "offline"

    def explain(
        self, issue: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Produce an explanation/fix/references for a single issue.

        If online mode is enabled the NIM inference endpoint will be called with a
        prompt constructed from the issue and context. The response is parsed into
        explanation/fix/references. On any failure the offline templates are used.
        """
        # reset last-explain flag
        try:
            self._last_explain_used_online = False
        except Exception:
            pass

        if self.mode == "nim" and self.online_available and self.nim is not None:
            try:
                out = self._explain_online(issue, context)
                # mark that we successfully used online path
                self._last_explain_used_online = True
                return out
            except Exception:
                logger.exception("Online LLM failed; falling back to offline templates")
                self._last_explain_used_online = False
                return self._explain_offline(issue, context)
        if (
            self.mode == "sagemaker"
            and self.online_available
            and self.sagemaker is not None
        ):
            try:
                out = self._explain_sagemaker(issue, context)
                self._last_explain_used_online = True
                return out
            except Exception:
                logger.exception(
                    "SageMaker LLM failed; falling back to offline templates"
                )
                self._last_explain_used_online = False
                return self._explain_offline(issue, context)

        return self._explain_offline(issue, context)

    def _explain_online(
        self, issue: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        # Build a structured prompt including KB/context if provided
        itype = issue.get("type", "Issue")
        snippet = issue.get("snippet", "")
        message = issue.get("message", "")
        # Build context: include KB summary and any retrieved snippets if available
        ctx_parts = []
        if context:
            kb = context.get("kb", {}) or {}
            if kb.get("summary"):
                ctx_parts.append(kb.get("summary"))
            # include any retrieved texts to provide concrete best-practices
            for r in (
                kb.get("retrieved", [])
                if isinstance(kb.get("retrieved", []), list)
                else []
            ):
                # r expected to be dict with 'text' or tuple-like
                if isinstance(r, dict) and r.get("text"):
                    ctx_parts.append(r.get("text"))
                elif isinstance(r, (list, tuple)) and len(r) > 2:
                    ctx_parts.append(r[2])

        ctx = "\n".join([p for p in ctx_parts if p])

        prompt = (
            f"You are a senior application security engineer. Explain the following code issue in simple language, "
            f"describe the impact, and provide a concise fix plus references.\n"
            f"Issue Type: {itype}\n"
            f"Line: {issue.get('line')}\n"
            f"Snippet: {snippet}\n"
            f"Message: {message}\n"
            f"Relevant Knowledge: \n{ctx}\n\n"
            "Return a JSON object with keys: explanation, fix, references (list of URLs)."
        )

        out_text = self.nim.explain(prompt, max_tokens=512)
        # Try to parse JSON from the model output
        try:
            import json

            parsed = json.loads(out_text)
            # ensure keys
            return {
                "explanation": (
                    parsed.get("explanation")
                    or parsed.get("explain")
                    or parsed.get("description")
                    or str(parsed)
                ),
                "fix": parsed.get("fix") or parsed.get("remediation") or "",
                "references": parsed.get("references") or parsed.get("refs") or [],
            }
        except Exception:
            # fallback: heuristically split the text into parts
            lines = out_text.splitlines()
            explanation = out_text
            fix = ""
            refs = []
            # look for 'Fix:' or 'Remediation:' markers
            for i, l in enumerate(lines):
                if l.lower().startswith("fix:") or l.lower().startswith("remediation:"):
                    fix = " ".join(lines[i:i+3])
                if l.lower().startswith("http"):
                    refs.append(l.strip())
            return {"explanation": explanation, "fix": fix, "references": refs}

    def _explain_sagemaker(
        self, issue: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        # reuse same prompt construction as _explain_online
        itype = issue.get("type", "Issue")
        snippet = issue.get("snippet", "")
        message = issue.get("message", "")
        ctx_parts = []
        if context:
            kb = context.get("kb", {}) or {}
            if kb.get("summary"):
                ctx_parts.append(kb.get("summary"))
            for r in (
                kb.get("retrieved", [])
                if isinstance(kb.get("retrieved", []), list)
                else []
            ):
                if isinstance(r, dict) and r.get("text"):
                    ctx_parts.append(r.get("text"))
                elif isinstance(r, (list, tuple)) and len(r) > 2:
                    ctx_parts.append(r[2])

        ctx = "\n".join([p for p in ctx_parts if p])

        prompt = (
            f"You are a senior application security engineer. Explain the following code issue in simple language, "
            f"describe the impact, and provide a concise fix plus references.\n"
            f"Issue Type: {itype}\n"
            f"Line: {issue.get('line')}\n"
            f"Snippet: {snippet}\n"
            f"Message: {message}\n"
            f"Relevant Knowledge: \n{ctx}\n\n"
            "Return a JSON object with keys: explanation, fix, references (list of URLs)."
        )

        out_text = self.sagemaker.explain(prompt, max_tokens=512)
        try:
            import json

            parsed = json.loads(out_text)
            return {
                "explanation": (
                    parsed.get("explanation")
                    or parsed.get("explain")
                    or parsed.get("description")
                    or str(parsed)
                ),
                "fix": parsed.get("fix") or parsed.get("remediation") or "",
                "references": parsed.get("references") or parsed.get("refs") or [],
            }
        except Exception:
            # fallback to heuristic
            lines = out_text.splitlines()
            explanation = out_text
            fix = ""
            refs = []
            for i, l in enumerate(lines):
                if l.lower().startswith("fix:") or l.lower().startswith("remediation:"):
                    fix = " ".join(lines[i:i+3])
                if l.lower().startswith("http"):
                    refs.append(l.strip())
            return {"explanation": explanation, "fix": fix, "references": refs}

    def _explain_offline(
        self, issue: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        itype = (issue.get("type") or issue.get("issue") or "Unknown").lower()
        snippet = issue.get("snippet") or ""

        templates = {
            # ---- Secrets / credentials ----
            "hardcoded secret": {
                "explanation": (
                    "This file contains a hardcoded secret or credential in source code which can be read "
                    "by anyone with repository access."
                ),
                "fix": (
                    "Remove the secret from source control. Use environment variables, a .env file kept "
                    "out of VCS, or a secret store (HashiCorp Vault, AWS Secrets Manager). "
                    "Rotate the credential immediately if it was committed."
                ),
                "references": [
                    "https://owasp.org/www-project-top-ten/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                ],
            },
            "hardcoded api key": {
                "explanation": (
                    "An API key is hardcoded in the source code. Anyone who reads the repository "
                    "can extract and abuse this key."
                ),
                "fix": (
                    "Move the API key to an environment variable or a secret manager. "
                    "Rotate the key immediately."
                ),
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                ],
            },
            "aws access key": {
                "explanation": (
                    "An AWS access key (AKIA prefix) was found in the source code. "
                    "This grants direct access to AWS resources."
                ),
                "fix": (
                    "Remove the key, rotate it via IAM console, and use IAM roles, "
                    "instance profiles, or environment variables instead."
                ),
                "references": [
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
                ],
            },
            "hardcoded password": {
                "explanation": (
                    "A password is hardcoded in the source code. This is a high-severity "
                    "credential leak risk."
                ),
                "fix": (
                    "Store passwords in a secrets manager or environment variable. "
                    "Use hashed passwords where applicable. Rotate the password."
                ),
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                ],
            },
            "jwt token": {
                "explanation": (
                    "A JWT token is embedded directly in code. JWTs can carry identity "
                    "claims and grant access to protected resources."
                ),
                "fix": (
                    "Never embed tokens in source code. Issue them at runtime via an "
                    "authentication flow and store in secure, HttpOnly cookies or "
                    "short-lived memory."
                ),
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
                ],
            },
            "private key": {
                "explanation": (
                    "A PEM-encoded private key was found in the source code. "
                    "Private keys must be kept confidential."
                ),
                "fix": (
                    "Move the private key to a secure key store (AWS KMS, HashiCorp Vault). "
                    "Regenerate the key pair if it was committed."
                ),
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html",
                ],
            },
            # ---- SQL injection ----
            "possible sql injection": {
                "explanation": (
                    "This code constructs SQL statements by concatenating strings or by formatting them "
                    "directly. Attackers can inject SQL fragments through inputs, leading to data leakage "
                    "or corruption."
                ),
                "fix": (
                    "Use parameterized queries (e.g., cursor.execute(sql, params)) or ORM query builders "
                    "to avoid direct string composition of SQL. Validate and sanitize inputs."
                ),
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                ],
            },
            "sql injection": {
                "explanation": (
                    "SQL queries are built using user-controlled input without parameterization, "
                    "allowing injection attacks."
                ),
                "fix": (
                    "Use prepared statements or ORM query builders. Never concatenate input into SQL."
                ),
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                ],
            },
            # ---- Insecure functions ----
            "insecure function usage": {
                "explanation": (
                    "Use of functions like eval() or exec() can execute arbitrary code and should be "
                    "avoided, especially on user-controlled inputs."
                ),
                "fix": (
                    "Replace eval/exec with safer alternatives. For parsing expressions use "
                    "ast.literal_eval or write a simple parser. Validate inputs strictly."
                ),
                "references": ["https://owasp.org/www-community/"],
            },
            "eval": {
                "explanation": (
                    "eval() interprets a string as code. If the string comes from user input, "
                    "attackers can execute arbitrary commands."
                ),
                "fix": (
                    "Use ast.literal_eval() for safe expression parsing, or a purpose-built "
                    "parser. Never eval() untrusted data."
                ),
                "references": ["https://owasp.org/www-community/"],
            },
            "exec": {
                "explanation": (
                    "exec() runs arbitrary Python code. If the code string is influenced by "
                    "external input, it enables remote code execution."
                ),
                "fix": (
                    "Avoid exec(). Use restricted execution environments or a safe DSL "
                    "if dynamic behaviour is needed."
                ),
                "references": ["https://owasp.org/www-community/"],
            },
            # ---- Deserialization ----
            "insecure deserialization": {
                "explanation": (
                    "Deserializing untrusted data with pickle, marshal, or yaml.load() can "
                    "lead to arbitrary code execution."
                ),
                "fix": (
                    "Use JSON for data exchange. If YAML is required, use yaml.safe_load(). "
                    "Never unpickle data from untrusted sources."
                ),
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
                ],
            },
            "pickle": {
                "explanation": (
                    "pickle.load(s) can execute arbitrary code during deserialization. "
                    "An attacker who controls the pickled data can achieve RCE."
                ),
                "fix": (
                    "Avoid pickle for untrusted data. Use JSON, MessagePack, or protobuf."
                ),
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
                ],
            },
            "yaml": {
                "explanation": (
                    "yaml.load() without SafeLoader can instantiate arbitrary Python objects, "
                    "leading to remote code execution."
                ),
                "fix": (
                    "Use yaml.safe_load() or pass Loader=yaml.SafeLoader."
                ),
                "references": [
                    "https://pyyaml.org/wiki/PyYAMLDocumentation",
                ],
            },
            # ---- Command injection / subprocess ----
            "suspicious subprocess call": {
                "explanation": (
                    "Calling subprocess APIs with unsanitized inputs or with shell=True can allow command "
                    "injection or execution of unintended commands."
                ),
                "fix": (
                    "Avoid shell=True and pass arguments as a list. Validate and sanitize any inputs "
                    "used in command construction."
                ),
                "references": ["https://cheatsheetseries.owasp.org/"],
            },
            "subprocess": {
                "explanation": (
                    "Using shell=True in subprocess calls passes the command through the system "
                    "shell, enabling shell injection attacks."
                ),
                "fix": (
                    "Pass command arguments as a list and avoid shell=True."
                ),
                "references": ["https://cheatsheetseries.owasp.org/"],
            },
            "os.system": {
                "explanation": (
                    "os.system() and os.popen() execute commands through the shell and are "
                    "vulnerable to injection if inputs are not sanitized."
                ),
                "fix": (
                    "Use subprocess.run() with a list of arguments instead of os.system()."
                ),
                "references": ["https://cheatsheetseries.owasp.org/"],
            },
            "command injection": {
                "explanation": (
                    "Command injection occurs when user input is passed unsanitized to a "
                    "system shell, allowing attackers to run arbitrary commands."
                ),
                "fix": (
                    "Never build shell commands from user input. Use subprocess with a list "
                    "of args and validate inputs."
                ),
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
                ],
            },
            "child_process": {
                "explanation": (
                    "Node.js child_process APIs (exec, spawn) can execute shell commands. "
                    "If inputs are unsanitized, this enables command injection."
                ),
                "fix": (
                    "Use execFile() or spawn() with arguments as an array. "
                    "Validate and sanitize all user-provided inputs."
                ),
                "references": ["https://cheatsheetseries.owasp.org/"],
            },
            # ---- Crypto / hash ----
            "deprecated hash": {
                "explanation": (
                    "MD5 and SHA1 are considered cryptographically broken or weak for collision "
                    "resistance and should not be used for security-sensitive hashing."
                ),
                "fix": (
                    "Use hashlib.sha256 or a stronger function and use salt + PBKDF2 / bcrypt / scrypt "
                    "/ Argon2 for password hashing."
                ),
                "references": ["https://owasp.org/www-project-top-ten/"],
            },
            "insecure random": {
                "explanation": (
                    "Python's random module is a PRNG not suitable for security. Using it to "
                    "generate tokens, keys, or passwords is predictable."
                ),
                "fix": (
                    "Use the secrets module (secrets.token_hex(), secrets.token_urlsafe()) "
                    "or os.urandom() for cryptographic randomness."
                ),
                "references": [
                    "https://docs.python.org/3/library/secrets.html",
                ],
            },
            # ---- Regex ----
            "insecure regex": {
                "explanation": (
                    "Overly-broad regex patterns like '.*' can match unintended input and can cause "
                    "catastrophic backtracking (ReDoS)."
                ),
                "fix": (
                    "Use more specific regexes and apply input length limits. Consider non-greedy "
                    "qualifiers and anchors as appropriate."
                ),
                "references": ["https://owasp.org/www-community/"],
            },
            # ---- XSS ----
            "xss": {
                "explanation": (
                    "Cross-Site Scripting (XSS) occurs when untrusted data is inserted into "
                    "a web page without proper escaping, letting attackers run scripts in "
                    "victims' browsers."
                ),
                "fix": (
                    "Use textContent instead of innerHTML. Sanitize with DOMPurify. "
                    "Set a strong Content-Security-Policy header."
                ),
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                ],
            },
            "innerhtml": {
                "explanation": (
                    "Setting innerHTML or using document.write with unsanitized input "
                    "can lead to DOM-based XSS."
                ),
                "fix": (
                    "Use textContent or createElement(). If HTML is needed, sanitize with "
                    "DOMPurify before insertion."
                ),
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                ],
            },
            # ---- TLS ----
            "tls": {
                "explanation": (
                    "Disabling TLS certificate verification (verify=False) allows "
                    "man-in-the-middle attacks."
                ),
                "fix": (
                    "Always verify TLS certificates. If a custom CA is needed, "
                    "pass it via the verify parameter or REQUESTS_CA_BUNDLE env."
                ),
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                ],
            },
            # ---- Debug mode ----
            "debug": {
                "explanation": (
                    "Running in debug mode in production exposes stack traces, environment "
                    "variables, and may enable interactive debuggers."
                ),
                "fix": (
                    "Set DEBUG=False and disable Flask/Django debug mode in production."
                ),
                "references": ["https://owasp.org/www-project-top-ten/"],
            },
            # ---- Path traversal ----
            "path traversal": {
                "explanation": (
                    "Accepting file paths from user input without validation can let "
                    "attackers read or overwrite arbitrary files via '..' sequences."
                ),
                "fix": (
                    "Canonicalize paths with os.path.realpath(), reject '..' components, "
                    "and restrict access to an allowed base directory."
                ),
                "references": [
                    "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
                ],
            },
            # ---- C/C++ dangerous functions ----
            "dangerous c function": {
                "explanation": (
                    "Functions like strcpy, gets, sprintf, and system lack bounds "
                    "checking or run shell commands, creating buffer overflow or "
                    "command injection risks."
                ),
                "fix": (
                    "Use bounds-checked alternatives: strncpy, snprintf, fgets. "
                    "Avoid system(); prefer fork+exec with sanitized arguments."
                ),
                "references": [
                    "https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard",
                ],
            },
            "dangerous function": {
                "explanation": (
                    "Use of unsafe C/C++ standard library functions can lead to buffer "
                    "overflows and other memory corruption vulnerabilities."
                ),
                "fix": (
                    "Replace with bounds-checked equivalents (strncpy, snprintf, fgets). "
                    "Use AddressSanitizer during development."
                ),
                "references": [
                    "https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard",
                ],
            },
            # ---- Temp files ----
            "tempfile": {
                "explanation": (
                    "mktemp() creates a predictable temporary filename, enabling race-condition "
                    "attacks (symlink attacks)."
                ),
                "fix": (
                    "Use mkstemp() or tempfile.NamedTemporaryFile() which create the file atomically."
                ),
                "references": ["https://owasp.org/www-community/"],
            },
            # ---- Assert for security ----
            "assert": {
                "explanation": (
                    "Python assert statements are removed when code runs with -O. Using them "
                    "for security checks means checks disappear in production."
                ),
                "fix": (
                    "Replace assert with explicit if/raise statements for access-control logic."
                ),
                "references": ["https://docs.python.org/3/reference/simple_stmts.html#the-assert-statement"],
            },
            # ---- Format string ----
            "format string": {
                "explanation": (
                    "Passing a user-controlled variable directly as a printf format string "
                    "allows attackers to read/write memory via format specifiers like %x, %n."
                ),
                "fix": (
                    "Always use a literal format string: printf(\"%s\", user_data)."
                ),
                "references": [
                    "https://owasp.org/www-community/attacks/Format_string_attack",
                ],
            },
        }

        # Try exact match first, then substring match
        choice = templates.get(itype, None)
        if not choice:
            for key, tmpl in templates.items():
                if key in itype or itype in key:
                    choice = tmpl
                    break

        if choice:
            return {
                "explanation": choice["explanation"],
                "fix": choice["fix"],
                "references": choice["references"],
            }

        return {
            "explanation": (
                f"Detected issue: '{issue.get('type') or issue.get('issue')}'. "
                f"{issue.get('message', '')} {snippet}"
            ),
            "fix": (
                "Investigate the finding and apply recommended best-practices (parameterization, "
                "secrets management, or safer library APIs)."
            ),
            "references": ["https://owasp.org/www-project-top-ten/"],
        }
