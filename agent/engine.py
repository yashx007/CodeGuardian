"""Comprehensive agent engine that orchestrates pattern-based scanning.

Covers: hardcoded secrets, SQL injection, insecure functions, command injection,
insecure deserialization, deprecated crypto, dangerous C/C++ APIs, JS-specific
issues, XSS, path traversal, insecure TLS, debug modes, and more.
"""

import re
from typing import Dict, List

from .nim_stub import RetrievalClient


class AgentEngine:
    def __init__(self):
        self.retriever = RetrievalClient()

    # ------------------------------------------------------------------
    # Internal helpers – each _check_* method appends to `issues` in-place
    # ------------------------------------------------------------------

    def _check_secrets(self, content: str, issues: List[Dict[str, str]]):
        """Detect hardcoded secrets, API keys, passwords, tokens, private keys."""
        hint = self.retriever.lookup("hardcoded secret")

        # API_KEY / aws_access_key_id literal strings
        if "API_KEY" in content or "aws_access_key_id" in content:
            issues.append({"issue": "Hardcoded API key detected", "suggestion": hint})

        # AWS AKIA access-key pattern
        if re.search(r'AKIA[0-9A-Z]{16,}', content):
            issues.append({"issue": "AWS access key detected (AKIA…)", "suggestion": hint})

        # Generic SECRET / TOKEN / PRIVATE_KEY variable assignments
        if re.search(
            r'(?i)\b(SECRET|TOKEN|AUTH_TOKEN|ACCESS_TOKEN|AWS_SECRET|PRIVATE_KEY|'
            r'CLIENT_SECRET|SECRET_KEY|ENCRYPTION_KEY|SIGNING_KEY)\b\s*=\s*["\']',
            content,
        ):
            issues.append({"issue": "Hardcoded secret/token variable detected", "suggestion": hint})

        # JWT tokens (eyJ… base-64 header)
        if re.search(r'eyJ[A-Za-z0-9_-]{10,}\.', content):
            issues.append({"issue": "Hardcoded JWT token detected", "suggestion": hint})

        # Password variable assignments
        if re.search(r'(?i)\b(password|passwd|pwd)\b\s*=\s*["\']', content):
            issues.append({"issue": "Hardcoded password detected", "suggestion": hint})

        # PEM private keys
        if re.search(r'-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', content):
            issues.append({"issue": "Private key embedded in source code", "suggestion": hint})

        # Generic long hex / base-64 secrets (>= 32 chars assigned to suspicious names)
        if re.search(
            r'(?i)\b(key|secret|token|credential)\b\s*=\s*["\'][A-Za-z0-9+/=_-]{32,}["\']',
            content,
        ):
            issues.append({"issue": "Possible long credential string detected", "suggestion": hint})

    def _check_sql_injection(self, content: str, issues: List[Dict[str, str]]):
        """Detect SQL injection via concatenation, f-strings, .format(), % formatting."""
        kws = ("SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "MERGE")
        if not any(kw in content.upper() for kw in kws):
            return
        hint = self.retriever.lookup("sql injection")
        sql_patterns = [
            r'["\']SELECT\b.*\+',
            r'f["\'].*SELECT\b.*\{',
            r'["\']SELECT\b.*\.format\s*\(',
            r'["\']SELECT\b.*%\s*[\(s]',
            r'["\']INSERT\b.*\+',
            r'f["\'].*INSERT\b.*\{',
            r'["\']INSERT\b.*\.format\s*\(',
            r'["\']UPDATE\b.*\+',
            r'f["\'].*UPDATE\b.*\{',
            r'["\']UPDATE\b.*\.format\s*\(',
            r'["\']DELETE\b.*\+',
            r'f["\'].*DELETE\b.*\{',
            r'["\']DELETE\b.*\.format\s*\(',
            r'["\']DROP\b.*\+',
            r'f["\'].*DROP\b.*\{',
        ]
        for pat in sql_patterns:
            if re.search(pat, content, re.IGNORECASE):
                issues.append({"issue": "Possible SQL injection", "suggestion": hint})
                return
        # JS template literal: `SELECT ... ${`
        if re.search(r'`SELECT\b.*\$\{', content, re.IGNORECASE):
            issues.append({"issue": "Possible SQL injection (template literal)", "suggestion": hint})

    def _check_python(self, content: str, issues: List[Dict[str, str]]):
        """Python-specific: eval, exec, pickle, yaml, assert, debug flags."""
        # eval()
        if re.search(r'\beval\s*\(', content):
            issues.append({
                "issue": "Use of eval() detected",
                "suggestion": self.retriever.lookup("insecure function"),
            })

        # exec()
        if re.search(r'\bexec\s*\(', content):
            issues.append({
                "issue": "Use of exec() detected",
                "suggestion": "Avoid exec(); use safer alternatives to run dynamic code.",
            })

        # pickle.load / loads
        if re.search(r'\bpickle\.loads?\s*\(', content):
            issues.append({
                "issue": "Insecure deserialization (pickle)",
                "suggestion": self.retriever.lookup("insecure deserialization"),
            })

        # yaml.load without SafeLoader
        if re.search(r'\byaml\.load\s*\(', content) and "SafeLoader" not in content and "safe_load" not in content:
            issues.append({
                "issue": "Insecure YAML deserialization",
                "suggestion": "Use yaml.safe_load() or pass Loader=yaml.SafeLoader to prevent arbitrary code execution.",
            })

        # marshal.loads
        if re.search(r'\bmarshal\.loads?\s*\(', content):
            issues.append({
                "issue": "Insecure deserialization (marshal)",
                "suggestion": "marshal is not safe for untrusted data. Use JSON or a validated serializer.",
            })

        # subprocess with shell=True
        if "shell=True" in content:
            issues.append({
                "issue": "subprocess with shell=True",
                "suggestion": self.retriever.lookup("command injection"),
            })

        # os.system / os.popen
        if re.search(r'\bos\.(system|popen)\s*\(', content):
            issues.append({
                "issue": "os.system/os.popen command execution",
                "suggestion": "Avoid os.system/os.popen; use subprocess with a list of args instead.",
            })

        # hashlib.md5 / sha1
        if re.search(r'hashlib\.(md5|sha1)\s*\(', content):
            issues.append({
                "issue": "Deprecated hash algorithm (MD5/SHA-1)",
                "suggestion": self.retriever.lookup("deprecated hash"),
            })

        # Insecure random for crypto
        if re.search(r'\brandom\.(random|randint|choice|randrange)\s*\(', content):
            if re.search(r'(?i)(token|secret|password|key|nonce|salt|otp)', content):
                issues.append({
                    "issue": "Insecure random used for security-sensitive value",
                    "suggestion": "Use secrets module or os.urandom() for cryptographic randomness.",
                })

        # assert used as security check
        if re.search(r'\bassert\b.*(auth|permission|role|admin|allowed)', content, re.IGNORECASE):
            issues.append({
                "issue": "Assert used for access control",
                "suggestion": "Assertions are stripped in optimized bytecode (-O). Use proper if/raise checks.",
            })

        # requests with verify=False
        if re.search(r'verify\s*=\s*False', content):
            issues.append({
                "issue": "TLS certificate verification disabled",
                "suggestion": self.retriever.lookup("insecure tls"),
            })

        # DEBUG = True / Flask debug mode
        if re.search(r'(?i)\bDEBUG\s*=\s*True\b', content) or re.search(r'\.run\s*\(.*debug\s*=\s*True', content):
            issues.append({
                "issue": "Debug mode enabled",
                "suggestion": "Disable debug mode in production. It can expose stack traces and enable code execution.",
            })

        # Insecure regex (overly broad)
        if re.search(r"re\.(compile|search|match)\s*\(\s*['\"](\.\*|\.\*\?|\^\.\*\$)['\"]", content):
            issues.append({
                "issue": "Overly broad regex pattern",
                "suggestion": self.retriever.lookup("insecure regex"),
            })

        # tempfile.mktemp (race condition)
        if re.search(r'\btempfile\.mktemp\s*\(', content):
            issues.append({
                "issue": "Insecure temp file creation (mktemp)",
                "suggestion": "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() to avoid race conditions.",
            })

        # open() combined with user input indicators
        if re.search(r'open\s*\(.*\b(request|input|argv|param|user|filename)\b', content, re.IGNORECASE):
            issues.append({
                "issue": "Potential path traversal via open()",
                "suggestion": self.retriever.lookup("path traversal"),
            })

    def _check_javascript(self, content: str, issues: List[Dict[str, str]]):
        """JavaScript / Node.js specific patterns."""
        # eval
        if re.search(r'\beval\s*\(', content):
            issues.append({
                "issue": "Use of eval() in JavaScript",
                "suggestion": self.retriever.lookup("insecure function"),
            })

        # new Function(...)
        if re.search(r'\bnew\s+Function\s*\(', content):
            issues.append({
                "issue": "Dynamic Function constructor (new Function)",
                "suggestion": "Avoid new Function(); it behaves like eval and can execute injected code.",
            })

        # child_process / exec / spawn
        if re.search(r"require\s*\(\s*['\"]child_process['\"]\s*\)", content):
            issues.append({
                "issue": "child_process module imported",
                "suggestion": self.retriever.lookup("command injection"),
            })
        if re.search(r'\bexec\s*\(', content) and "child_process" in content:
            issues.append({
                "issue": "child_process.exec() – command injection risk",
                "suggestion": "Prefer execFile() and pass args as array; validate all inputs.",
            })

        # innerHTML / document.write (XSS)
        if re.search(r'\binnerHTML\s*=', content) or re.search(r'\bdocument\.write\s*\(', content):
            issues.append({
                "issue": "DOM-based XSS risk (innerHTML/document.write)",
                "suggestion": self.retriever.lookup("xss"),
            })

        # dangerouslySetInnerHTML (React)
        if "dangerouslySetInnerHTML" in content:
            issues.append({
                "issue": "React dangerouslySetInnerHTML (XSS risk)",
                "suggestion": "Sanitize content with DOMPurify before using dangerouslySetInnerHTML.",
            })

        # hardcoded secrets in JS
        if re.search(r'(?i)\b(password|api_key|secret|token)\b\s*[:=]\s*["\']', content):
            issues.append({
                "issue": "Hardcoded secret in JavaScript",
                "suggestion": self.retriever.lookup("hardcoded secret"),
            })

    def _check_c_cpp(self, content: str, issues: List[Dict[str, str]]):
        """C / C++ dangerous functions and patterns."""
        dangerous_c = {
            "strcpy":  "Use strncpy() or strlcpy() to prevent buffer overflow.",
            "strcat":  "Use strncat() or strlcat() to prevent buffer overflow.",
            "sprintf": "Use snprintf() to prevent buffer overflow.",
            "gets":    "Use fgets() instead; gets() has no bounds checking.",
            "scanf":   "Use fgets()+sscanf or limit width specifiers to prevent overflow.",
            "system":  "Avoid system(); use exec-family functions with explicit arguments.",
            "popen":   "Avoid popen(); use pipe()+fork()+exec for better control.",
            "mktemp":  "Use mkstemp() to avoid temp-file race conditions.",
        }
        for func, fix in dangerous_c.items():
            if re.search(rf'\b{func}\s*\(', content):
                issues.append({"issue": f"Dangerous C function: {func}()", "suggestion": fix})

        # Format-string vulnerability: printf(variable) without format
        if re.search(r'\bprintf\s*\(\s*[a-zA-Z_]\w*\s*\)', content):
            issues.append({
                "issue": "Potential format-string vulnerability (printf with variable)",
                "suggestion": "Always pass a literal format string: printf(\"%s\", var).",
            })

        # Hardcoded passwords in C
        if re.search(r'(?i)\b(password|passwd)\b.*=\s*"', content):
            issues.append({
                "issue": "Hardcoded password in C/C++ source",
                "suggestion": self.retriever.lookup("hardcoded secret"),
            })

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def scan_code(self, filename: str, content: str) -> Dict[str, object]:
        """Run comprehensive pattern checks + retrieval hints.

        Returns a dict with 'issues' (list) plus legacy 'issue'/'suggestion'
        for backwards compatibility.
        """
        issues: List[Dict[str, str]] = []
        lower_name = filename.lower()

        # ---- Universal checks (all languages) ----
        self._check_secrets(content, issues)
        self._check_sql_injection(content, issues)

        # ---- Language-specific checks ----
        if lower_name.endswith((".py", ".pyw")):
            self._check_python(content, issues)
        elif lower_name.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
            self._check_javascript(content, issues)
        elif lower_name.endswith((".c", ".cpp", ".cc", ".cxx", ".h", ".hpp")):
            self._check_c_cpp(content, issues)
        else:
            # Unknown extension – run Python + JS + C checks to be safe
            self._check_python(content, issues)
            self._check_javascript(content, issues)
            self._check_c_cpp(content, issues)

        # ---- Deduplicate issues (same issue text) ----
        seen = set()
        unique: List[Dict[str, str]] = []
        for item in issues:
            key = item["issue"]
            if key not in seen:
                seen.add(key)
                unique.append(item)
        issues = unique

        # ---- Fallback ----
        if not issues:
            return {
                "issue": "No obvious issues found",
                "suggestion": "No action required",
                "issues": [],
            }

        return {
            "issue": issues[0]["issue"],
            "suggestion": issues[0]["suggestion"],
            "issues": issues,
        }


engine = AgentEngine()
