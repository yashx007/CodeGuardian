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
        "examples": ["API_KEY = 'abcd1234'", "password = 'hunter2'"],
        "fix": "Move secrets to environment variables or a secrets manager (AWS Secrets Manager, Hashicorp Vault). Use scoped short-lived credentials.",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            "https://owasp.org/www-project-top-ten/",
        ],
    },
    "possible sql injection": {
        "summary": "Unparameterized SQL or string-built queries can allow SQL injection attacks. Prefer parameterized queries or ORM APIs.",
        "examples": ["cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")"],
        "fix": "Use parameterized queries (prepared statements) or an ORM. Validate and sanitize user inputs, use least-privilege DB users.",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://owasp.org/www-community/attacks/SQL_Injection"
        ],
    },
    "insecure function usage": {
        "summary": "Dynamic code execution functions (eval/exec) may execute attacker-controlled input. Use safer parsing libraries or restricted evaluators.",
        "examples": ["eval(user_input)", "exec(code_str)"],
        "fix": "Avoid eval/exec. Use safe interpreters, whitelist allowed operations, or parse inputs with a structured parser.",
        "references": ["https://owasp.org/www-community/"],
    },
    "deprecated hash": {
        "summary": "Weak hashing algorithms like MD5/SHA1 are unsuitable for security-sensitive purposes. Use SHA-2/3 or password-specific KDFs.",
        "examples": ["hashlib.md5(data).hexdigest()"],
        "fix": "Use hashlib.sha256 or a password KDF like bcrypt/scrypt/argon2 for passwords. Migrate stored hashes where possible.",
        "references": ["https://www.ipa.go.jp/security/english/", "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"],
    },
    "suspicious subprocess call": {
        "summary": "Using subprocess APIs with shell=True or untrusted string inputs can lead to command injection. Pass args as a list and validate inputs.",
        "examples": ["subprocess.run(cmd, shell=True)", "os.system(user_input)"] ,
        "fix": "Avoid shell=True. Pass arguments as lists, validate or canonicalize inputs, and prefer high-level libraries.",
        "references": ["https://cheatsheetseries.owasp.org/"],
    },
    "insecure regex": {
        "summary": "Overly-broad regex patterns can cause catastrophic backtracking and unintended matches. Use anchors and limit quantifiers.",
        "examples": ["re.match('(a+)+b', s)", "unbounded quantifiers"] ,
        "fix": "Use non-backtracking engines, add bounds to quantifiers, or use safer parsing logic.",
        "references": ["https://owasp.org/www-community/"],
    },
    "broken access control": {
        "summary": "Broken access control allows users to act outside of their intended permissions. Always enforce authorization checks on the server side.",
        "examples": ["/users/1234/profile accessible to other users"],
        "fix": "Enforce authorization checks consistently on the server, use object-level ACLs, avoid relying on client-side controls.",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html", "https://owasp.org/www-project-top-ten/"],
    },
    "cross site scripting": {
        "summary": "Cross-Site Scripting (XSS) occurs when applications include untrusted data in web pages without proper validation or escaping.",
        "examples": ["document.write(user_input)", "innerHTML = user_content"],
        "fix": "Escape output, use context-aware encoding, and use CSP headers. Prefer safe templating engines that auto-escape.",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
    },
    "security misconfiguration": {
        "summary": "Security misconfiguration covers a wide range of issues including default credentials, open cloud storage, and unnecessary features enabled in production.",
        "examples": ["debug mode enabled in production", "default admin passwords"],
        "fix": "Harden defaults, disable debug endpoints, rotate credentials, and enforce secure defaults in CI/CD.",
        "references": ["https://owasp.org/www-project-top-ten/"],
    },
    "insufficient logging": {
        "summary": "Insufficient logging and monitoring delays detection and response to security incidents. Ensure important events are logged and monitored.",
        "examples": ["no audit log for failed login attempts"],
        "fix": "Log security-relevant events, centralize logs, and configure alerts for suspicious activity. Avoid logging secrets.",
        "references": ["https://cheatsheetseries.owasp.org/"],
    },
    # Additional high-value KB entries
    "open redirect": {
        "summary": "Open redirect vulnerabilities occur when an application redirects users to untrusted URLs based on user input.",
        "examples": ["/redirect?url=https://phish.example.com"],
        "fix": "Whitelist redirect targets or use internal mapping IDs instead of raw URLs.",
        "references": ["https://owasp.org/www-community/attacks/Redirection_attack"]
    },
    "insecure deserialization": {
        "summary": "Deserializing untrusted data can lead to remote code execution or state manipulation.",
        "examples": ["pickle.loads(untrusted_bytes)"],
        "fix": "Avoid insecure serializers, use safe formats (JSON) and explicit schema validation.",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Deserialization_Cheat_Sheet.html"]
    },
    "unencrypted sensitive data": {
        "summary": "Sensitive data in transit or at rest should be encrypted using modern algorithms and TLS.",
        "examples": ["HTTP endpoints without TLS", "storing PII in plaintext"],
        "fix": "Enable TLS, encrypt sensitive fields at rest, and use strong key management.",
        "references": ["https://owasp.org/www-project-top-ten/"]
    },
    "insufficient input validation": {
        "summary": "Failing to validate input allows many classes of bugs and security issues (injection, overflow, logic bugs).",
        "fix": "Validate inputs against an allowlist, enforce types and length limits, and use schema validation libraries.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "server side request forgery": {
        "summary": "SSRF allows attackers to make requests from the server to internal services. Often arises when URLs are user-controlled.",
        "examples": ["fetch(user_supplied_url)"],
        "fix": "Validate and restrict outbound requests, use allowlists and timeouts, and isolate network access for fetchers.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    # More curated entries to broaden retrieval coverage
    "csrf": {
        "summary": "Cross-Site Request Forgery (CSRF) tricks authenticated users into making unintended state-changing requests.",
        "examples": ["<img src=\"https://app.example.com/transfer?amt=100\">"],
        "fix": "Use anti-CSRF tokens, SameSite cookies, and require re-authentication for sensitive actions.",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"]
    },
    "xxe": {
        "summary": "XML External Entity (XXE) processing can allow disclosure of local files or SSRF when XML parsers resolve external entities.",
        "examples": ["<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"],
        "fix": "Disable external entity processing or use safer parsing libraries configured to disallow DTDs.",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"]
    },
    "path traversal": {
        "summary": "If file paths are constructed from user input, attackers can traverse directories and access unintended files.",
        "examples": ["open('/uploads/' + user_path)", "..\\..\\etc\\passwd"],
        "fix": "Normalize and validate paths, restrict to a safe base directory, and remove ../ sequences.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "insecure cookie": {
        "summary": "Cookies missing Secure/HttpOnly/SameSite flags can be exposed to JavaScript or sent over insecure channels.",
        "fix": "Set HttpOnly, Secure, and appropriate SameSite attributes for session cookies.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "clickjacking": {
        "summary": "Clickjacking allows UI redressing attacks by embedding the site in frames on attacker-controlled pages.",
        "fix": "Send X-Frame-Options or Content-Security-Policy frame-ancestors to prevent framing.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "broken cryptography": {
        "summary": "Using weak algorithms, improper key sizes, or insecure modes can break confidentiality or integrity.",
        "fix": "Use vetted cryptographic libraries, follow current crypto best practices, and prefer AEAD modes (e.g., AES-GCM).",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"]
    },
    "token leakage": {
        "summary": "Tokens (session tokens, API keys) passed in URLs or logs can be exposed to third parties.",
        "fix": "Avoid putting secrets in URLs, redact tokens in logs, and expire tokens frequently.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "rate limiting missing": {
        "summary": "Lack of rate limiting can enable brute-force, scraping, or abuse of endpoints.",
        "fix": "Implement per-IP and per-account rate limits and progressive backoff on failed auth attempts.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "large file upload": {
        "summary": "Unrestricted file uploads can exhaust resources or allow storage of malicious content.",
        "fix": "Enforce file size limits, validate content types, scan files for malware, and store uploads outside the web root.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "insecure cors": {
        "summary": "Broad CORS policies (e.g., Access-Control-Allow-Origin: *) can expose APIs to untrusted web origins.",
        "fix": "Limit allowed origins and methods; prefer exact origins or dynamic allowlist checks.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "improper error handling": {
        "summary": "Detailed error messages can leak internal implementation details, stack traces, or sensitive data.",
        "fix": "Return generic error messages to clients and log detailed errors securely on the server side.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "weak password policy": {
        "summary": "Allowing weak passwords increases risk of account takeover.",
        "fix": "Enforce minimum length, complexity, and use password strength checks; support MFA.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "exposed debug endpoint": {
        "summary": "Debug endpoints (debug toolbar, REPLs) should never be enabled in production as they expose internals.",
        "fix": "Disable debug features in production builds and gate them behind safe developer-only flags.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "directory listing": {
        "summary": "If directory listing is enabled, attackers can discover files and sensitive resources." ,
        "fix": "Disable directory listing on web servers and ensure indices are not exposed.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "missing security headers": {
        "summary": "Absence of headers like Content-Security-Policy, X-Content-Type-Options, and Strict-Transport-Security lowers protection.",
        "fix": "Add appropriate security headers with conservative defaults and review them periodically.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "weak tls ciphers": {
        "summary": "Using outdated TLS versions or weak cipher suites reduces transport security.",
        "fix": "Disable TLS < 1.2 and weak ciphers; use strong ciphers and keep server software updated.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "improper input sanitization": {
        "summary": "Failing to canonicalize and sanitize inputs can enable injection attacks across many vectors.",
        "fix": "Normalize inputs, enforce strict schemas, and escape or validate before use in sensitive contexts.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    # Additional curated items to push KB to 50+ entries
    "insecure direct object reference": {
        "summary": "Insecure Direct Object Reference (IDOR) occurs when user-controlled identifiers allow access to resources belonging to others.",
        "examples": ["/invoices/12345 where IDs are guessable"],
        "fix": "Enforce object-level authorization checks and use non-guessable identifiers or access controls on the server side.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "server side template injection": {
        "summary": "Server-Side Template Injection (SSTI) arises when untrusted input is evaluated by a template engine, potentially leading to RCE.",
        "examples": ["render_template(user_input)", "{{7*7}}"],
        "fix": "Do not evaluate user input in templates. Use safe templating engines and escape or whitelist variables.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "supply chain dependency tampering": {
        "summary": "Compromised dependencies (npm/pypi/maven) can introduce malicious code into your build or runtime.",
        "fix": "Pin dependency versions, use signing/verification, run supply-chain scans, and prefer vetted packages.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "improper authentication": {
        "summary": "Weak or missing authentication checks allow unauthorized access and account takeover.",
        "fix": "Use proven authentication libraries, enforce strong password and session controls, and implement MFA.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "missing multi factor authentication": {
        "summary": "Not offering or requiring MFA increases the risk of account compromise from credential theft.",
        "fix": "Offer and encourage MFA, and require it for high-risk operations.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "improper session management": {
        "summary": "Sessions that aren't invalidated, rotated, or bound to the user context can be hijacked.",
        "fix": "Rotate session identifiers after privilege changes, set secure cookie flags, and invalidate on logout.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "weak randomness": {
        "summary": "Using weak RNGs for tokens or keys (e.g., random.random()) can lead to predictable secrets.",
        "fix": "Use cryptographically secure RNGs from the OS (secrets module, /dev/urandom, CryptGenRandom).",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "missing rate limiting on auth": {
        "summary": "Without rate limiting, authentication endpoints can be brute-forced or abused.",
        "fix": "Apply IP- and account-based rate limits, introduce exponential backoff and lockouts.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "insecure dependency versions": {
        "summary": "Using outdated libraries with known CVEs exposes applications to known exploits.",
        "fix": "Keep dependencies up-to-date, run vulnerability scanners, and apply patches promptly.",
        "references": ["https://owasp.org/www-project-top-ten/"]
    },
    "improper certificate validation": {
        "summary": "Skipping TLS certificate validation allows man-in-the-middle attacks.",
        "examples": ["requests.get(url, verify=False)", "rejectUnauthorized: false"],
        "fix": "Always validate TLS certificates and use pinned roots where appropriate.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "insecure mobile storage": {
        "summary": "Storing secrets on mobile devices without encryption or OS-provided secure storage can leak credentials.",
        "fix": "Use platform keychains/keystore and encrypt sensitive data at rest.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "exposed backup or git artifacts": {
        "summary": "Backup files (.bak, .old) or leftover .git directories can leak source or credentials.",
        "fix": "Remove or restrict access to backups and ensure VCS metadata is not served by web servers.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "zip slip": {
        "summary": "Unsafe extraction of archive contents can overwrite arbitrary files via ../ paths (Zip Slip).",
        "fix": "Validate and sanitize extracted paths; restrict extraction to a safe directory and canonicalize paths.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "format string vulnerability": {
        "summary": "Uncontrolled format strings (e.g., printf(user_input)) can leak memory or crash programs.",
        "fix": "Do not use user input as format strings; use safe formatting APIs and validate inputs.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "integer overflow": {
        "summary": "Unchecked integer operations can overflow, leading to buffer sizing errors or logic bugs.",
        "fix": "Validate numeric ranges, use safe libraries, and check boundaries before allocating buffers.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "improper cloud permissions": {
        "summary": "Overly-permissive IAM or cloud roles can let attackers escalate access across services.",
        "fix": "Apply least-privilege IAM, separate duties, and audit cloud permissions regularly.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "exposed api keys in build": {
        "summary": "Embedding API keys in build artifacts or CI logs can leak credentials to third parties.",
        "fix": "Use secret variables in CI, redact logs, and avoid writing secrets into build outputs.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "certificate pinning missing": {
        "summary": "Mobile or embedded clients that don't pin TLS certificates can be susceptible to MITM via rogue CAs.",
        "fix": "Consider certificate pinning for high-security clients and monitor CA trust changes.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "race condition in critical path": {
        "summary": "Race conditions in file or resource access can lead to TOCTOU or privilege escalation.",
        "fix": "Use atomic operations, locks, and design for concurrency safety in critical paths.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "privilege escalation": {
        "summary": "Flaws that let unprivileged users perform privileged actions compromise system integrity.",
        "fix": "Harden permission checks, validate role transitions, and audit privilege boundaries.",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "backup credentials stored in repo": {
        "summary": "Credentials accidentally checked into repositories in backup files lead to long-lived secrets exposure.",
        "fix": "Rotate any exposed credentials and remove them from history (git filter-branch or BFG).",
        "references": ["https://cheatsheetseries.owasp.org/"]
    },
    "missing content security policy": {
        "summary": "Not setting a Content-Security-Policy allows more vectors for XSS and resource injection.",
        "fix": "Define a strict CSP that restricts script and resource origins and use nonce/hashing for inline scripts where needed.",
        "references": ["https://cheatsheetseries.owasp.org/"]
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
