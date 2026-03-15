"""
═══════════════════════════════════════════════════════════════
  CYBRAIN — Complete Vulnerability Scanner
  OWASP Top 10 2025 + CWE/SANS Top 25 + Extra Checks
  PFE Master 2 — Information Security
  NO AI used here — pure technical detection only
═══════════════════════════════════════════════════════════════
"""

import requests
import re
import json
import base64
import time
import urllib3
from urllib.parse import (
    urlparse, urlencode, urlunparse, parse_qs
)

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)

# ── SQL error signatures ────────────────────────────────────
DB_ERRORS = [
    "sql syntax", "mysql_fetch", "mysql_num_rows",
    "sqlite", "ora-", "pg_query", "pg_exec",
    "microsoft ole db", "syntax error near",
    "unclosed quotation mark", "quoted string not properly",
    "you have an error in your sql",
    "warning: mysql", "jdbc", "sqlexception",
    "odbc", "db2", "division by zero",
    "invalid query", "supplied argument is not",
    "mysqli_", "mssql_", "pg_connect",
    "mysql error", "database error",
]

# ── XSS payloads ────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert('xss_cybrain_2025')</script>",
    "<img src=x onerror=alert(1)>",
    '"><svg onload=alert(1)>',
    "<body onload=alert(1)>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<iframe src=javascript:alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "javascript:alert(document.domain)",
    "<details open ontoggle=alert(1)>",
    "<math><mtext></math><img src=x onerror=alert(1)>",
]

# ── SQLi payloads ────────────────────────────────────────────
SQLI_PAYLOADS = [
    ("'",                       "Single quote"),
    ("''",                      "Double quote"),
    ("1' OR '1'='1",            "OR bypass"),
    ("1' OR '1'='1'--",         "OR bypass comment"),
    ("1' ORDER BY 100--",       "ORDER BY probe"),
    ("' UNION SELECT NULL--",   "UNION probe"),
    ("' UNION SELECT NULL,NULL--","UNION 2col"),
    ("admin'--",                "Comment bypass"),
    ("' OR 1=1--",              "OR 1=1"),
    ("1; WAITFOR DELAY '0:0:2'--", "Time-based"),
    ("1' AND SLEEP(2)--",       "MySQL sleep"),
    ("1) OR (1=1",              "Parenthesis bypass"),
]

# ── Command injection payloads ───────────────────────────────
CMD_PAYLOADS = [
    ("; id",                "Semicolon id"),
    ("| id",                "Pipe id"),
    ("; cat /etc/passwd",   "Read passwd"),
    ("`id`",                "Backtick"),
    ("$(id)",               "Dollar paren"),
    ("; sleep 3",           "Sleep test"),
    ("| whoami",            "Whoami"),
    ("; uname -a",          "System info"),
    ("& ipconfig",          "Windows ipconfig"),
    ("| dir",               "Windows dir"),
]
CMD_SIGNS = [
    "root:", "bin/bash", "bin/sh", "www-data",
    "uid=", "gid=", "total ", "windows ip",
    "volume in drive", "directory of",
    "linux", "darwin", "freebsd",
]

# ── SSTI payloads ────────────────────────────────────────────
SSTI_PAYLOADS = {
    "{{7*7}}":                   "49",
    "{{7*'7'}}":                 "7777777",
    "${7*7}":                    "49",
    "#{7*7}":                    "49",
    "<%= 7*7 %>":                "49",
    "${{'a','b'}|join}":         "ab",
    "{{config}}":                "Config",
    "@(7*7)":                    "49",
    "*{7*7}":                    "49",
    "{{''.__class__}}":          "str",
}

# ── Path traversal payloads ──────────────────────────────────
PATH_TRAVERSAL = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "%252e%252e%252f",
]

# ── XXE payloads ─────────────────────────────────────────────
XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<test>&xxe;</test>"""

# ── Sensitive files ──────────────────────────────────────────
SENSITIVE_FILES = {
    "/.env":              ("CRITICAL", "password|secret|key|db_"),
    "/.git/config":       ("CRITICAL", "[core]"),
    "/.git/HEAD":         ("HIGH",     "ref:"),
    "/.git/COMMIT_EDITMSG":("HIGH",    ""),
    "/phpinfo.php":       ("HIGH",     "phpinfo"),
    "/info.php":          ("HIGH",     "phpinfo"),
    "/test.php":          ("MEDIUM",   ""),
    "/server-status":     ("HIGH",     "apache server status"),
    "/server-info":       ("HIGH",     "apache"),
    "/.htaccess":         ("MEDIUM",   "rewriterule|deny"),
    "/backup.zip":        ("CRITICAL", ""),
    "/backup.tar.gz":     ("CRITICAL", ""),
    "/dump.sql":          ("CRITICAL", "insert into|create table"),
    "/database.sql":      ("CRITICAL", "insert into|create table"),
    "/config.php":        ("CRITICAL", "password|db_pass"),
    "/config.php.bak":    ("CRITICAL", "password"),
    "/wp-config.php":     ("CRITICAL", "db_password"),
    "/web.config":        ("HIGH",     "connectionstring|password"),
    "/.DS_Store":         ("LOW",      ""),
    "/robots.txt":        ("LOW",      "user-agent"),
    "/sitemap.xml":       ("LOW",      ""),
    "/crossdomain.xml":   ("MEDIUM",   "allow-access-from"),
    "/swagger.json":      ("LOW",      "swagger"),
    "/swagger.yaml":      ("LOW",      "swagger"),
    "/api/swagger":       ("LOW",      "swagger"),
    "/openapi.json":      ("LOW",      "openapi"),
    "/.well-known/":      ("LOW",      ""),
    "/actuator":          ("HIGH",     ""),
    "/actuator/env":      ("CRITICAL", ""),
    "/actuator/health":   ("MEDIUM",   ""),
    "/metrics":           ("MEDIUM",   ""),
    "/.ssh/id_rsa":       ("CRITICAL", "-----begin"),
    "/id_rsa":            ("CRITICAL", "-----begin"),
    "/private.key":       ("CRITICAL", "-----begin"),
    "/certificate.pem":   ("HIGH",     "-----begin"),
    "/.npmrc":            ("HIGH",     "_auth|token"),
    "/.dockerenv":        ("MEDIUM",   ""),
    "/docker-compose.yml":("HIGH",     "password|secret"),
    "/Dockerfile":        ("LOW",      ""),
    "/package.json":      ("LOW",      ""),
    "/composer.json":     ("LOW",      ""),
    "/.bash_history":     ("CRITICAL", ""),
    "/.zsh_history":      ("CRITICAL", ""),
}


class OWASPChecker:
    """
    OWASP Top 10 2025 + CWE/SANS Top 25.
    Pure technical detection — zero AI involvement.
    """

    def __init__(self, target_url, session,
                 timeout=20):
        self.target  = (
            target_url.split("#")[0].rstrip("/")
        )
        self.base    = self._base(self.target)
        self.session = session
        self.timeout = timeout
        self.findings = []

    def _base(self, url):
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def _get(self, url, extra_headers=None, **kw):
        h = {"User-Agent": BROWSER_UA}
        if extra_headers:
            h.update(extra_headers)
        try:
            return self.session.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                headers=h,
                **kw
            )
        except Exception:
            return None

    def _post(self, url, json_data=None,
              data=None, headers=None, **kw):
        h = {"User-Agent": BROWSER_UA}
        if headers:
            h.update(headers)
        try:
            return self.session.post(
                url,
                json=json_data,
                data=data,
                headers=h,
                timeout=self.timeout,
                verify=False,
                **kw
            )
        except Exception:
            return None

    def _add(self, owasp_id, owasp_name, severity,
             title, description, evidence="",
             fix="", cwe="", cvss="", sans=""):
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
            "sans":        sans,
            "target":      self.target,
        })

    def _build_url(self, path="", params=None):
        p = urlparse(self.target)
        path = path or p.path
        q = urlencode(params) if params else ""
        return urlunparse(
            (p.scheme, p.netloc, path, "", q, "")
        )

    def run_all(self):
        """
        Run all checks.
        OWASP 2025 order:
          A01 Broken Access Control
          A02 Security Misconfiguration
          A03 Software Supply Chain
          A04 Cryptographic Failures
          A05 Injection
          A06 Insecure Design
          A07 Authentication Failures
          A08 Integrity Failures
          A09 Logging Failures
          A10 Mishandling Exceptions
        + CWE/SANS extras
        """
        print("[CYBRAIN] Starting full scan...")
        print(
            f"[CYBRAIN] Target: {self.target}"
        )

        resp = self._get(self.target)
        if resp is None:
            print("[CYBRAIN] Target unreachable.")
            return self.findings

        print(f"[CYBRAIN] Status: {resp.status_code}")

        # ── OWASP 2025 ──────────────────────────────────
        self._a01_broken_access_control(resp)
        self._a02_security_misconfiguration(resp)
        self._a03_supply_chain(resp)
        self._a04_cryptographic_failures(resp)
        self._a05_injection(resp)
        self._a06_insecure_design(resp)
        self._a07_auth_failures(resp)
        self._a08_integrity_failures(resp)
        self._a09_logging_failures(resp)
        self._a10_mishandling_exceptions(resp)

        # ── CWE/SANS EXTRAS ─────────────────────────────
        self._cwe_path_traversal()
        self._cwe_xxe()
        self._cwe_open_redirect()
        self._cwe_clickjacking(resp)
        self._cwe_cors_misconfig(resp)
        self._cwe_host_header_injection()
        self._cwe_http_methods()
        self._cwe_unrestricted_upload()

        print(
            f"[CYBRAIN] Done. "
            f"{len(self.findings)} findings."
        )
        return self.findings

    # ════════════════════════════════════════════════ #
    #  A01:2025 — BROKEN ACCESS CONTROL
    # ════════════════════════════════════════════════ #
    def _a01_broken_access_control(self, resp):
        print("[A01:2025] Broken Access Control...")

        # IDOR — object ID enumeration
        idor_paths = [
            "/api/users/1",   "/api/users/2",
            "/api/user/1",    "/rest/user/1",
            "/user/1",        "/account/1",
            "/profile/1",     "/order/1",
            "/api/orders/1",  "/invoice/1",
            "/api/v1/users/1","/api/v2/users/1",
        ]
        for path in idor_paths:
            r = self._get(f"{self.base}{path}")
            if r and r.status_code == 200:
                body = r.text.lower()
                if any(s in body for s in [
                    "email", "username", "password",
                    "address", "phone", "credit",
                    "firstname", "lastname", "dob",
                ]):
                    self._add(
                        "A01:2025",
                        "Broken Access Control",
                        "HIGH",
                        "Insecure Direct Object Reference (IDOR)",
                        f"Endpoint {path} returns user PII without "
                        "authorization. Any user can access other "
                        "users' data by changing the ID parameter.",
                        evidence=(
                            f"GET {self.base}{path} "
                            "→ 200 + user data (email/username/etc)"
                        ),
                        fix=(
                            "1. Implement server-side authorization "
                            "on EVERY data endpoint.\n"
                            "2. Verify authenticated user owns the "
                            "requested resource.\n"
                            "3. Use UUIDs instead of sequential IDs.\n"
                            "4. Log all access attempts."
                        ),
                        cwe="CWE-639",
                        cvss="8.1",
                        sans="SANS #1"
                    )
                    break

        # Admin panel without auth
        admin_paths = [
            "/admin",         "/admin/",
            "/administrator", "/admin/dashboard",
            "/admin/users",   "/wp-admin",
            "/manager",       "/console",
            "/api/admin",     "/backend",
            "/admin/panel",   "/superadmin",
            "/admincp",       "/controlpanel",
            "/cpanel",        "/moderator",
        ]
        for path in admin_paths:
            r = self._get(f"{self.base}{path}")
            if r and r.status_code == 200:
                body = r.text.lower()
                if any(s in body for s in [
                    "dashboard", "admin", "manage",
                    "users", "settings", "panel",
                    "statistics", "reports", "logout",
                ]):
                    self._add(
                        "A01:2025",
                        "Broken Access Control",
                        "CRITICAL",
                        f"Admin Panel Accessible: {path}",
                        f"The admin panel at {path} is accessible "
                        "without authentication. Complete "
                        "administrative access exposed.",
                        evidence=(
                            f"GET {self.base}{path} "
                            "→ 200 + admin content"
                        ),
                        fix=(
                            "1. Require auth + admin role "
                            "on all admin routes.\n"
                            "2. Implement IP allowlisting.\n"
                            "3. Add MFA for admin access.\n"
                            "4. Use separate admin subdomain."
                        ),
                        cwe="CWE-284",
                        cvss="9.8",
                        sans="SANS #1"
                    )
                    break

        # Missing CSRF tokens
        if "<form" in resp.text.lower():
            has_csrf = any(
                t in resp.text.lower() for t in [
                    "csrf", "_token", "xsrf",
                    "authenticity_token",
                    "requestverificationtoken",
                    "__requestverificationtoken",
                    "csrfmiddlewaretoken",
                ]
            )
            if not has_csrf:
                self._add(
                    "A01:2025",
                    "Broken Access Control",
                    "HIGH",
                    "Missing CSRF Protection",
                    "HTML forms detected without CSRF tokens. "
                    "Attackers can forge state-changing requests "
                    "(password change, fund transfer, data deletion) "
                    "on behalf of authenticated users.",
                    fix=(
                        "1. Add per-session CSRF token to all forms.\n"
                        "2. Validate server-side on every POST/PUT/DELETE.\n"
                        "3. Set SameSite=Strict on session cookies.\n"
                        "4. Use double-submit cookie pattern."
                    ),
                    cwe="CWE-352",
                    cvss="8.8",
                    sans="SANS #9"
                )

        # Forced browsing / path prediction
        sensitive_paths = [
            "/backup", "/old", "/test",
            "/dev", "/staging", "/beta",
            "/tmp", "/temp", "/cache",
            "/logs", "/log", "/debug",
        ]
        for path in sensitive_paths:
            r = self._get(f"{self.base}{path}")
            if r and r.status_code == 200:
                if len(r.text) > 200:
                    self._add(
                        "A01:2025",
                        "Broken Access Control",
                        "MEDIUM",
                        f"Forced Browsing: {path}",
                        f"Path {path} is accessible without "
                        "authorization and returns content. "
                        "May expose internal files or data.",
                        evidence=(
                            f"GET {self.base}{path} "
                            f"→ 200 ({len(r.text)} bytes)"
                        ),
                        fix=(
                            "Restrict access to sensitive paths. "
                            "Return 401/403 for unauthorized access. "
                            "Implement proper access control lists."
                        ),
                        cwe="CWE-425",
                        cvss="5.3"
                    )
                    break

        # HTTP method override bypass
        for hdr in [
            "X-HTTP-Method-Override",
            "X-Method-Override",
            "X-HTTP-Method",
            "_method",
        ]:
            r = self._get(
                self.target,
                extra_headers={hdr: "DELETE"}
            )
            if r and r.status_code not in [405, 501]:
                self._add(
                    "A01:2025",
                    "Broken Access Control",
                    "MEDIUM",
                    f"HTTP Method Override ({hdr})",
                    "Server accepts method override headers. "
                    "Attackers can bypass method-based "
                    "access controls and WAF rules.",
                    evidence=(
                        f"{hdr}: DELETE → {r.status_code}"
                    ),
                    fix=(
                        "Disable method override headers. "
                        "Validate HTTP methods at framework level."
                    ),
                    cwe="CWE-650",
                    cvss="6.5"
                )
                break

    # ════════════════════════════════════════════════ #
    #  A02:2025 — SECURITY MISCONFIGURATION
    # ════════════════════════════════════════════════ #
    def _a02_security_misconfiguration(self, resp):
        print("[A02:2025] Security Misconfiguration...")

        # Missing security headers
        required = {
            "Content-Security-Policy":   ("HIGH",   "CWE-693",
                "Prevents XSS and data injection attacks."),
            "Strict-Transport-Security": ("HIGH",   "CWE-319",
                "Forces HTTPS — prevents SSL stripping."),
            "X-Frame-Options":           ("MEDIUM", "CWE-1021",
                "Prevents clickjacking attacks."),
            "X-Content-Type-Options":    ("MEDIUM", "CWE-693",
                "Prevents MIME-type sniffing."),
            "X-XSS-Protection":          ("MEDIUM", "CWE-693",
                "Legacy XSS filter for older browsers."),
            "Referrer-Policy":           ("LOW",    "CWE-200",
                "Controls referrer information leakage."),
            "Permissions-Policy":        ("LOW",    "CWE-284",
                "Restricts browser feature access."),
            "Cross-Origin-Opener-Policy":("LOW",    "CWE-346",
                "Prevents cross-origin attacks."),
        }
        missing = [
            (h, s, c, d)
            for h, (s, c, d) in required.items()
            if h not in resp.headers
        ]
        if missing:
            worst = (
                "HIGH" if any(
                    s == "HIGH" for _, s, _, _ in missing
                ) else "MEDIUM"
            )
            header_list = "\n• ".join(
                f"{h} [{s}] — {d}"
                for h, s, _, d in missing
            )
            self._add(
                "A02:2025",
                "Security Misconfiguration",
                worst,
                "Missing HTTP Security Headers",
                f"The following security headers are absent "
                f"from the HTTP response:\n• {header_list}",
                fix=(
                    "Add to Apache httpd.conf or .htaccess:\n"
                    'Header always set Content-Security-Policy "default-src \'self\'"\n'
                    "Header always set Strict-Transport-Security "
                    '"max-age=31536000; includeSubDomains; preload"\n'
                    'Header always set X-Frame-Options "DENY"\n'
                    'Header always set X-Content-Type-Options "nosniff"\n'
                    'Header always set Referrer-Policy "strict-origin-when-cross-origin"'
                ),
                cwe="CWE-693",
                cvss="6.5"
            )

        # Server version disclosure
        for h in ("Server", "X-Powered-By",
                  "X-AspNet-Version", "X-Generator",
                  "X-Runtime", "X-Version"):
            if h in resp.headers:
                self._add(
                    "A02:2025",
                    "Security Misconfiguration",
                    "LOW",
                    f"Server Technology Disclosure ({h})",
                    f"Response header {h}: {resp.headers[h]} "
                    "reveals server technology. Attackers use "
                    "this to find known CVEs for this version.",
                    evidence=f"{h}: {resp.headers[h]}",
                    fix=(
                        "Apache: ServerTokens Prod + "
                        "ServerSignature Off\n"
                        "Nginx: server_tokens off\n"
                        "PHP: expose_php = Off in php.ini"
                    ),
                    cwe="CWE-200",
                    cvss="5.3"
                )

        # Sensitive files
        for path, (sev, kw) in SENSITIVE_FILES.items():
            r = self._get(f"{self.base}{path}")
            if r and r.status_code == 200:
                content = r.text.lower()
                if not kw or any(
                    k in content
                    for k in kw.split("|")
                ):
                    self._add(
                        "A02:2025",
                        "Security Misconfiguration",
                        sev,
                        f"Sensitive File Exposed: {path}",
                        f"Path {self.base}{path} is publicly "
                        "accessible (HTTP 200). May expose "
                        "credentials, source code, or server "
                        "configuration.",
                        evidence=(
                            f"GET {self.base}{path} → 200 "
                            f"({len(r.text)} bytes)"
                        ),
                        fix=(
                            f"Remove {path} from web root. "
                            "Block access with .htaccess:\n"
                            "<Files .env>\n"
                            "  Require all denied\n"
                            "</Files>"
                        ),
                        cwe="CWE-200",
                        cvss="7.5"
                    )

        # Directory listing
        if ("Index of /" in resp.text and
                "<title>Index of" in resp.text):
            self._add(
                "A02:2025",
                "Security Misconfiguration",
                "HIGH",
                "Directory Listing Enabled",
                "Web server displays raw directory contents. "
                "Attackers can enumerate all files including "
                "backups, configs, and source code.",
                fix=(
                    "Apache: add Options -Indexes to "
                    "httpd.conf or .htaccess"
                ),
                cwe="CWE-548",
                cvss="7.5"
            )

        # CORS wildcard
        acao = resp.headers.get(
            "Access-Control-Allow-Origin", ""
        )
        acac = resp.headers.get(
            "Access-Control-Allow-Credentials", ""
        )
        if acao == "*":
            self._add(
                "A02:2025",
                "Security Misconfiguration",
                "MEDIUM",
                "CORS Wildcard Origin",
                "Access-Control-Allow-Origin: * permits "
                "any website to read API responses. "
                "Sensitive data may be exposed to malicious "
                "third-party websites.",
                evidence="Access-Control-Allow-Origin: *",
                fix=(
                    "Restrict CORS to trusted origins:\n"
                    "Header set Access-Control-Allow-Origin "
                    '"https://yourdomain.com"'
                ),
                cwe="CWE-942",
                cvss="6.5"
            )
        if acao and acac.lower() == "true":
            self._add(
                "A02:2025",
                "Security Misconfiguration",
                "HIGH",
                "CORS With Credentials Misconfiguration",
                f"Credentials allowed for origin {acao}. "
                "If origin is user-controlled, enables "
                "complete session hijacking.",
                evidence=(
                    f"ACAO: {acao} | ACAC: true"
                ),
                fix=(
                    "Validate Origin against strict server-side "
                    "allowlist. Never reflect user-supplied origins."
                ),
                cwe="CWE-942",
                cvss="8.1"
            )

        # Debug mode
        debug_signs = [
            "traceback", "stack trace",
            "werkzeug debugger", "django debug",
            "exception at line", "rails debug",
            "laravel debugbar", "xdebug",
        ]
        for path in [
            "/?debug=true", "/debug",
            "/?XDEBUG_SESSION_START=1"
        ]:
            r = self._get(f"{self.base}{path}")
            if r and any(
                s in r.text.lower()
                for s in debug_signs
            ):
                self._add(
                    "A02:2025",
                    "Security Misconfiguration",
                    "HIGH",
                    "Debug Mode Active in Production",
                    "Application debug mode is enabled. "
                    "Full stack traces, file paths, and "
                    "internal logic are exposed to users.",
                    evidence=(
                        f"Debug content found at {path}"
                    ),
                    fix=(
                        "Set DEBUG=False in production.\n"
                        "Use custom error pages.\n"
                        "Never expose stack traces to users."
                    ),
                    cwe="CWE-94",
                    cvss="7.5"
                )
                break

    # ════════════════════════════════════════════════ #
    #  A03:2025 — SOFTWARE SUPPLY CHAIN FAILURES
    # ════════════════════════════════════════════════ #
    def _a03_supply_chain(self, resp):
        print("[A03:2025] Software Supply Chain...")

        # Outdated library versions
        version_patterns = {
            "jQuery":     r"jquery[/-]([\d.]+)",
            "Bootstrap":  r"bootstrap[/-]([\d.]+)",
            "Angular":    r"angular[/-]([\d.]+)",
            "React":      r"react[/-]([\d.]+)",
            "Vue":        r"vue[/-]([\d.]+)",
            "Apache":     r"Apache/([\d.]+)",
            "Nginx":      r"nginx/([\d.]+)",
            "PHP":        r"PHP/([\d.]+)",
            "OpenSSL":    r"OpenSSL/([\d.]+)",
            "WordPress":  r"wp-content|wp-includes",
            "Drupal":     r"drupal[/-]([\d.]+)",
            "Joomla":     r"joomla[/-]([\d.]+)",
            "Laravel":    r"laravel[/-]([\d.]+)",
            "Django":     r"django[/-]([\d.]+)",
            "Spring":     r"spring[/-]([\d.]+)",
            "Log4j":      r"log4j[/-]([\d.]+)",
            "Struts":     r"struts[/-]([\d.]+)",
        }

        # Known vulnerable versions (CWE-1104)
        critical_versions = {
            "Log4j": ["2.0", "2.1", "2.2", "2.3",
                      "2.4", "2.5", "2.6", "2.7",
                      "2.8", "2.9", "2.10", "2.11",
                      "2.12", "2.13", "2.14"],  # Log4Shell
            "Apache": ["2.4.49", "2.4.50"],  # Path traversal
            "jQuery": ["1.", "2.", "3.0", "3.1",
                       "3.2", "3.3", "3.4", "3.5"],
        }

        all_text = (
            resp.text +
            str(dict(resp.headers))
        )

        for tech, pattern in version_patterns.items():
            match = re.search(
                pattern, all_text, re.IGNORECASE
            )
            if match:
                version = (
                    match.group(1)
                    if match.lastindex and
                    match.lastindex >= 1
                    else "detected"
                )

                # Check if critically vulnerable
                sev = "MEDIUM"
                cve_note = ""
                if tech in critical_versions:
                    for vuln_ver in critical_versions[tech]:
                        if version.startswith(vuln_ver):
                            sev = "CRITICAL"
                            if tech == "Log4j":
                                cve_note = (
                                    " CRITICAL: "
                                    "CVE-2021-44228 "
                                    "(Log4Shell RCE)"
                                )
                            elif tech == "Apache":
                                cve_note = (
                                    " CRITICAL: "
                                    "CVE-2021-41773 "
                                    "(Path Traversal)"
                                )
                            break

                self._add(
                    "A03:2025",
                    "Software Supply Chain Failures",
                    sev,
                    f"Component Detected: {tech} "
                    f"{version}{cve_note}",
                    f"{tech} version {version} detected in "
                    "responses. Outdated or vulnerable "
                    "components are a primary attack vector. "
                    f"{'⚠️ Known critical CVE!' if sev == 'CRITICAL' else ''}",
                    evidence=f"{tech} {version} found in response",
                    fix=(
                        f"Update {tech} to latest stable version.\n"
                        "Use a dependency scanner "
                        "(OWASP Dependency-Check, Snyk).\n"
                        "Subscribe to security advisories.\n"
                        "Remove version from HTTP headers."
                    ),
                    cwe="CWE-1104",
                    cvss="9.8" if sev == "CRITICAL" else "6.8"
                )

        # External scripts without SRI
        sri_pattern = re.compile(
            r'<script[^>]+src=["\']'
            r'(https?://[^"\']+)["\'][^>]*>',
            re.IGNORECASE
        )
        sri_count = 0
        for match in sri_pattern.finditer(resp.text):
            src = match.group(1)
            pos = resp.text.find(src)
            nearby = resp.text[
                max(0, pos-50):pos+150
            ]
            has_sri = "integrity=" in nearby.lower()
            is_external = not src.startswith(self.base)
            if is_external and not has_sri:
                sri_count += 1
                if sri_count <= 3:
                    self._add(
                        "A03:2025",
                        "Software Supply Chain Failures",
                        "MEDIUM",
                        "External Script Without SRI Hash",
                        f"Script from {src[:80]} loaded "
                        "without Subresource Integrity hash. "
                        "CDN compromise would execute malicious "
                        "code on all visitors.",
                        evidence=(
                            f'<script src="{src[:80]}">'
                        ),
                        fix=(
                            "Add integrity attribute:\n"
                            '<script src="..." '
                            'integrity="sha384-HASH" '
                            'crossorigin="anonymous">\n'
                            "Generate hash: "
                            "https://www.srihash.org/"
                        ),
                        cwe="CWE-353",
                        cvss="6.8"
                    )

    # ════════════════════════════════════════════════ #
    #  A04:2025 — CRYPTOGRAPHIC FAILURES
    # ════════════════════════════════════════════════ #
    def _a04_cryptographic_failures(self, resp):
        print("[A04:2025] Cryptographic Failures...")

        # Plain HTTP
        if self.target.startswith("http://"):
            self._add(
                "A04:2025",
                "Cryptographic Failures",
                "HIGH",
                "Unencrypted HTTP Protocol",
                "Site served over HTTP. Passwords, session "
                "tokens, and all data transmitted in plaintext. "
                "Susceptible to MITM interception and credential "
                "theft on any network.",
                evidence="Protocol: HTTP (no TLS/SSL)",
                fix=(
                    "1. Get free TLS cert: certbot --apache\n"
                    "2. Redirect HTTP to HTTPS in Apache:\n"
                    "   Redirect permanent / https://domain.com/\n"
                    "3. Add HSTS header:\n"
                    "   Header always set Strict-Transport-Security "
                    '"max-age=31536000; includeSubDomains; preload"'
                ),
                cwe="CWE-319",
                cvss="7.5"
            )

        # Insecure cookies
        raw_cookie = resp.headers.get("Set-Cookie", "")
        if raw_cookie:
            issues = []
            if "httponly" not in raw_cookie.lower():
                issues.append(
                    "HttpOnly missing — JS can steal cookie "
                    "(XSS cookie theft)"
                )
            if "secure" not in raw_cookie.lower():
                issues.append(
                    "Secure missing — sent over plain HTTP"
                )
            if "samesite" not in raw_cookie.lower():
                issues.append(
                    "SameSite missing — CSRF attacks possible"
                )
            if issues:
                self._add(
                    "A04:2025",
                    "Cryptographic Failures",
                    "HIGH",
                    "Insecure Cookie Configuration",
                    "Session cookies missing security flags:\n• "
                    + "\n• ".join(issues),
                    evidence=(
                        f"Set-Cookie: {raw_cookie[:150]}"
                    ),
                    fix=(
                        "Set cookies with all security flags:\n"
                        "Set-Cookie: session=VALUE; "
                        "HttpOnly; Secure; SameSite=Strict; "
                        "Path=/; Max-Age=3600"
                    ),
                    cwe="CWE-1004",
                    cvss="7.3"
                )

        # JWT token analysis
        jwt_re = re.compile(
            r'eyJ[A-Za-z0-9_-]+\.'
            r'eyJ[A-Za-z0-9_-]+\.'
            r'[A-Za-z0-9_-]*'
        )
        text_to_search = (
            resp.text + str(dict(resp.headers))
        )
        jwt_match = jwt_re.search(text_to_search)
        if jwt_match:
            token = jwt_match.group(0)
            try:
                seg = token.split(".")[0]
                seg += "=" * (4 - len(seg) % 4)
                hdr = json.loads(
                    base64.urlsafe_b64decode(seg)
                )
                alg = hdr.get("alg", "")
                if alg.lower() == "none":
                    self._add(
                        "A04:2025",
                        "Cryptographic Failures",
                        "CRITICAL",
                        "JWT Algorithm:None — Signature Bypass",
                        "JWT token with alg:none detected. "
                        "Signature verification is disabled. "
                        "Attacker can forge any token including "
                        "admin tokens without the secret key.",
                        evidence=f"JWT header: {hdr}",
                        fix=(
                            "1. Reject tokens with alg:none.\n"
                            "2. Enforce RS256/HS256 server-side.\n"
                            "3. Maintain strict algorithm whitelist.\n"
                            "4. Use a battle-tested JWT library."
                        ),
                        cwe="CWE-347",
                        cvss="9.8"
                    )
                elif alg in ("HS256", "HS384", "HS512"):
                    self._add(
                        "A04:2025",
                        "Cryptographic Failures",
                        "LOW",
                        f"JWT Symmetric Algorithm ({alg})",
                        f"JWT uses symmetric algorithm {alg}. "
                        "Weak secrets can be brute-forced offline "
                        "using tools like hashcat.",
                        evidence=f"JWT alg: {alg}",
                        fix=(
                            "Use RS256 (asymmetric) for public APIs. "
                            "Ensure secret is 256+ bits random."
                        ),
                        cwe="CWE-327",
                        cvss="5.3"
                    )
            except Exception:
                pass

        # Sensitive data in URL parameters
        sensitive_params = [
            "password", "passwd", "pwd", "pass",
            "token", "secret", "api_key", "apikey",
            "auth", "authorization", "credit_card",
            "cc", "cvv", "ssn", "private_key",
        ]
        for param in sensitive_params:
            if f"{param}=" in self.target.lower():
                self._add(
                    "A04:2025",
                    "Cryptographic Failures",
                    "HIGH",
                    f"Sensitive Data in URL ({param})",
                    f"Sensitive parameter '{param}' passed in URL. "
                    "Logged in server access logs, browser history, "
                    "and referrer headers. Anyone with log access "
                    "can steal these values.",
                    evidence=f"URL contains: {param}=...",
                    fix=(
                        "Never pass sensitive data in URL params.\n"
                        "Use POST body with HTTPS.\n"
                        "Implement proper session management."
                    ),
                    cwe="CWE-312",
                    cvss="7.5"
                )
                break

    # ════════════════════════════════════════════════ #
    #  A05:2025 — INJECTION
    # ════════════════════════════════════════════════ #
    def _a05_injection(self, resp):
        print("[A05:2025] Injection (SQLi/XSS/Cmd/SSTI)...")

        # ── SQL INJECTION ────────────────────────────
        found_sqli = False
        params_to_test = [
            "id", "user", "username", "q",
            "search", "query", "page", "cat",
            "category", "item", "product",
            "order", "sort", "filter", "key",
            "name", "email", "type", "action",
        ]

        for payload, pname in SQLI_PAYLOADS:
            if found_sqli:
                break
            for param in params_to_test:
                url = self._build_url(
                    params={param: payload}
                )
                r = self._get(url)
                if r and any(
                    e in r.text.lower()
                    for e in DB_ERRORS
                ):
                    self._add(
                        "A05:2025",
                        "Injection",
                        "CRITICAL",
                        "SQL Injection (Error-Based)",
                        f"SQL injection via parameter '{param}'. "
                        "Database error leaked in HTTP response. "
                        "Full database extraction, authentication "
                        "bypass, and potential OS command execution "
                        "are possible.",
                        evidence=(
                            f"?{param}={payload} → DB error in response"
                        ),
                        fix=(
                            "1. Use parameterized queries ONLY:\n"
                            "   cursor.execute('SELECT * FROM t "
                            "WHERE id=?', (user_id,))\n"
                            "2. Never concatenate user input into SQL.\n"
                            "3. Use an ORM (SQLAlchemy, Hibernate).\n"
                            "4. Apply least-privilege DB accounts.\n"
                            "5. Deploy a WAF as additional layer."
                        ),
                        cwe="CWE-89",
                        cvss="9.8",
                        sans="SANS #3"
                    )
                    found_sqli = True
                    break

        # Login endpoint SQL injection
        if not found_sqli:
            login_paths = [
                "/login", "/api/login",
                "/rest/user/login", "/auth",
                "/auth/login", "/signin",
                "/user/login", "/api/v1/login",
                "/api/v2/login", "/authenticate",
            ]
            sqli_creds = [
                {"email":    "' OR 1=1--",
                 "password": "x"},
                {"username": "admin'--",
                 "password": "x"},
                {"email":    "admin'--",
                 "password": "x"},
                {"login":    "' OR '1'='1",
                 "password": "x"},
                {"user":     "admin' #",
                 "password": "x"},
            ]
            for path in login_paths:
                if found_sqli:
                    break
                for creds in sqli_creds:
                    r = self._post(
                        f"{self.base}{path}",
                        json_data=creds
                    )
                    if r and r.status_code == 200:
                        body = r.text.lower()
                        if any(s in body for s in [
                            "token", "bearer",
                            "authentication", "success",
                            "welcome", "logged",
                            "dashboard", "access_token",
                            "refresh_token",
                        ]):
                            self._add(
                                "A05:2025",
                                "Injection",
                                "CRITICAL",
                                "SQL Injection — Auth Bypass",
                                f"Login at {path} bypassed via "
                                "SQL injection. Authentication "
                                "completely defeated — attacker "
                                "gains admin access with no "
                                "valid credentials.",
                                evidence=(
                                    f"POST {path} payload: "
                                    f"{list(creds.values())[0]}"
                                    " → 200 + auth token"
                                ),
                                fix=(
                                    "Use parameterized queries.\n"
                                    "Hash passwords with bcrypt/argon2.\n"
                                    "Never build SQL from user input."
                                ),
                                cwe="CWE-89",
                                cvss="9.8",
                                sans="SANS #3"
                            )
                            found_sqli = True
                            break

        # ── REFLECTED XSS ────────────────────────────
        xss_paths = [
            "/search", "/", "/index.php",
            "/query", "/find", "/results",
            "/q", "/s", "/filter",
        ]
        found_xss = False
        for path in xss_paths:
            if found_xss:
                break
            for payload in XSS_PAYLOADS:
                url = self._build_url(
                    path=path if path != "/" else "",
                    params={
                        "q":      payload,
                        "search": payload,
                        "query":  payload,
                        "s":      payload,
                        "term":   payload,
                    }
                )
                r = self._get(url)
                if r and payload in r.text:
                    self._add(
                        "A05:2025",
                        "Injection",
                        "HIGH",
                        "Reflected Cross-Site Scripting (XSS)",
                        f"XSS at {path} — user input returned "
                        "in HTML response without encoding. "
                        "Attacker can steal session cookies, "
                        "redirect victims, perform actions on "
                        "their behalf, or deliver malware.",
                        evidence=(
                            f"Path: {path} | "
                            f"Payload reflected: {payload[:60]}"
                        ),
                        fix=(
                            "1. Apply HTML encoding on ALL user output:\n"
                            "   Python: markupsafe.escape(input)\n"
                            "   PHP: htmlspecialchars($input, ENT_QUOTES)\n"
                            "2. Implement strict Content-Security-Policy.\n"
                            "3. Use auto-escaping template engines.\n"
                            "4. Validate and sanitize all inputs."
                        ),
                        cwe="CWE-79",
                        cvss="7.4",
                        sans="SANS #2"
                    )
                    found_xss = True
                    break

        # ── COMMAND INJECTION ────────────────────────
        cmd_params = [
            "host", "ip", "cmd", "exec",
            "ping", "query", "file", "path",
            "dir", "command", "run", "shell",
            "system", "execute", "input",
        ]
        for payload, pname in CMD_PAYLOADS:
            found = False
            for param in cmd_params:
                url = self._build_url(
                    params={param: payload}
                )
                r = self._get(url)
                if r and any(
                    s in r.text for s in CMD_SIGNS
                ):
                    self._add(
                        "A05:2025",
                        "Injection",
                        "CRITICAL",
                        "OS Command Injection",
                        f"Command injection via '{param}'. "
                        "Server executed OS command — output "
                        "visible in response. Complete server "
                        "compromise is possible.",
                        evidence=(
                            f"?{param}={payload} "
                            "→ command output in response"
                        ),
                        fix=(
                            "NEVER pass user input to OS commands.\n"
                            "Use language APIs instead of shell.\n"
                            "Apply strict input whitelist.\n"
                            "Run app as least-privilege user.\n"
                            "Use subprocess with shell=False."
                        ),
                        cwe="CWE-78",
                        cvss="10.0",
                        sans="SANS #5"
                    )
                    found = True
                    break
            if found:
                break

        # ── SERVER-SIDE TEMPLATE INJECTION ───────────
        for payload, expected in SSTI_PAYLOADS.items():
            url = self._build_url(
                params={
                    "q":    payload,
                    "name": payload,
                    "msg":  payload,
                }
            )
            r = self._get(url)
            if r and expected in r.text:
                self._add(
                    "A05:2025",
                    "Injection",
                    "CRITICAL",
                    "Server-Side Template Injection (SSTI)",
                    f"Template expression {payload} was evaluated "
                    f"server-side (result: {expected}). "
                    "RCE is achievable in Jinja2, Twig, Freemarker, "
                    "Smarty, and most other template engines.",
                    evidence=(
                        f"Payload: {payload} "
                        f"→ Result: {expected}"
                    ),
                    fix=(
                        "Never render user input as template code.\n"
                        "Use sandboxed template environments.\n"
                        "Validate all inputs before template rendering.\n"
                        "Separate user data from template logic."
                    ),
                    cwe="CWE-94",
                    cvss="10.0"
                )
                break

        # ── LDAP INJECTION ───────────────────────────
        ldap_payloads = [
            "*)(uid=*))(|(uid=*",
            "*()|%26'",
            "admin)(&)",
            "*)(|(password=*)",
        ]
        ldap_errors = [
            "ldap", "javax.naming", "ldapexception",
            "invalid dn", "no such object",
            "ldap_bind", "00002030",
        ]
        for payload in ldap_payloads:
            for param in ["user", "username",
                          "email", "login"]:
                url = self._build_url(
                    params={param: payload}
                )
                r = self._get(url)
                if r and any(
                    e in r.text.lower()
                    for e in ldap_errors
                ):
                    self._add(
                        "A05:2025",
                        "Injection",
                        "HIGH",
                        "LDAP Injection",
                        f"LDAP injection via '{param}'. "
                        "LDAP error leaked in response. "
                        "Directory information disclosure "
                        "and authentication bypass possible.",
                        evidence=(
                            f"?{param}={payload} → LDAP error"
                        ),
                        fix=(
                            "Escape special LDAP characters "
                            "in all user inputs: "
                            "( ) * \\ NUL / @ = + < > , ; "
                            "Use parameterized LDAP queries."
                        ),
                        cwe="CWE-90",
                        cvss="8.1"
                    )
                    break

    # ════════════════════════════════════════════════ #
    #  A06:2025 — INSECURE DESIGN
    # ════════════════════════════════════════════════ #
    def _a06_insecure_design(self, resp):
        print("[A06:2025] Insecure Design...")

        # Rate limiting check (brute force)
        login_path = None
        for path in [
            "/login", "/api/login",
            "/rest/user/login", "/signin",
            "/api/v1/auth", "/api/v2/login",
        ]:
            r = self._get(f"{self.base}{path}")
            if r and r.status_code in [200, 405]:
                login_path = path
                break

        if login_path:
            blocked = False
            for i in range(12):
                r = self._post(
                    f"{self.base}{login_path}",
                    json_data={
                        "email":    f"test{i}@test.com",
                        "password": "WrongPass123!"
                    }
                )
                if r and r.status_code == 429:
                    blocked = True
                    break
                time.sleep(0.2)

            if not blocked:
                self._add(
                    "A06:2025",
                    "Insecure Design",
                    "HIGH",
                    "No Rate Limiting — Brute Force Risk",
                    f"Login endpoint {login_path} does not "
                    "enforce rate limiting. 12 consecutive "
                    "failed attempts were not blocked. "
                    "Password brute-force and credential "
                    "stuffing attacks are possible.",
                    evidence=(
                        f"12 requests to {login_path} — "
                        "no HTTP 429 received"
                    ),
                    fix=(
                        "1. Implement rate limiting "
                        "(max 5 attempts/minute).\n"
                        "2. Account lockout after N failures.\n"
                        "3. Add CAPTCHA after 3 failures.\n"
                        "4. Use progressive delays.\n"
                        "5. Alert on suspicious patterns."
                    ),
                    cwe="CWE-307",
                    cvss="7.5"
                )

        # User enumeration via password reset
        reset_paths = [
            "/forgot-password", "/reset-password",
            "/forgot_password", "/password-reset",
            "/api/forgot", "/password/reset",
            "/api/password/reset",
        ]
        for path in reset_paths:
            r1 = self._post(
                f"{self.base}{path}",
                json_data={"email": "admin@test.com"}
            )
            r2 = self._post(
                f"{self.base}{path}",
                json_data={
                    "email": "notexist_xyz123@nowhere.io"
                }
            )
            if (r1 and r2 and
                    r1.status_code == r2.status_code and
                    abs(len(r1.text) - len(r2.text)) > 10):
                self._add(
                    "A06:2025",
                    "Insecure Design",
                    "MEDIUM",
                    "User Enumeration via Password Reset",
                    f"Password reset at {path} returns "
                    "different responses for valid vs invalid "
                    "emails. Attackers can enumerate valid "
                    "accounts for targeted attacks.",
                    evidence=(
                        f"Valid email: {len(r1.text)} bytes | "
                        f"Invalid email: {len(r2.text)} bytes"
                    ),
                    fix=(
                        "Return identical response for all "
                        "password reset attempts.\n"
                        'Example: "If this email exists, '
                        'you will receive a reset link."\n'
                        "Add rate limiting to prevent enumeration."
                    ),
                    cwe="CWE-204",
                    cvss="5.3"
                )
                break

    # ════════════════════════════════════════════════ #
    #  A07:2025 — AUTHENTICATION FAILURES
    # ════════════════════════════════════════════════ #
    def _a07_auth_failures(self, resp):
        print("[A07:2025] Authentication Failures...")

        # Default credentials test
        default_creds = [
            ("admin",  "admin"),
            ("admin",  "password"),
            ("admin",  "123456"),
            ("admin",  "admin123"),
            ("admin",  "Password1"),
            ("admin",  ""),
            ("root",   "root"),
            ("root",   "toor"),
            ("test",   "test"),
            ("guest",  "guest"),
            ("user",   "user"),
            ("demo",   "demo"),
            ("admin",  "letmein"),
            ("admin",  "qwerty"),
            ("admin",  "welcome"),
        ]
        login_paths = [
            "/login", "/api/login",
            "/rest/user/login", "/signin",
            "/api/v1/auth/login",
        ]
        found_default = False
        for path in login_paths:
            if found_default:
                break
            for uname, passwd in default_creds:
                for payload in [
                    {"username": uname,
                     "password": passwd},
                    {"email":
                     f"{uname}@example.com",
                     "password": passwd},
                    {"login":    uname,
                     "password": passwd},
                ]:
                    r = self._post(
                        f"{self.base}{path}",
                        json_data=payload
                    )
                    if r and r.status_code == 200:
                        body = r.text.lower()
                        if any(s in body for s in [
                            "token", "bearer",
                            "access_token", "success",
                            "dashboard", "welcome",
                            "logged in", "auth",
                        ]):
                            self._add(
                                "A07:2025",
                                "Authentication Failures",
                                "CRITICAL",
                                "Default Credentials Accepted",
                                f"Application accepted "
                                f"{uname}:{passwd} at {path}. "
                                "Admin access granted without "
                                "any exploitation technique.",
                                evidence=(
                                    f"POST {path} "
                                    f"{uname}:{passwd} "
                                    "→ 200 + auth token"
                                ),
                                fix=(
                                    "1. Remove all default creds.\n"
                                    "2. Force password change on "
                                    "first login.\n"
                                    "3. Enforce strong password "
                                    "policy.\n"
                                    "4. Implement MFA.\n"
                                    "5. Lock after 5 failures."
                                ),
                                cwe="CWE-521",
                                cvss="9.8",
                                sans="SANS #13"
                            )
                            found_default = True
                            break
                if found_default:
                    break

        # Weak session tokens
        for name, value in resp.cookies.items():
            if any(k in name.lower() for k in [
                "session", "sess", "auth",
                "token", "sid", "user_id",
            ]):
                if (len(value) < 16 or
                        value.isdigit() or
                        value.isalpha() or
                        value in [
                            "1", "true", "admin",
                            "user", "test",
                        ]):
                    self._add(
                        "A07:2025",
                        "Authentication Failures",
                        "HIGH",
                        f"Weak Session Token: {name}",
                        f"Session token '{name}' appears "
                        f"weak/predictable (value: {value[:20]}). "
                        "Brute-force or prediction attacks "
                        "can hijack any user session.",
                        evidence=(
                            f"{name}={value[:30]}..."
                        ),
                        fix=(
                            "Use cryptographically secure "
                            "random tokens (256+ bits).\n"
                            "Use framework session management.\n"
                            "Regenerate session ID on login."
                        ),
                        cvss="7.5"
                    )

    # ════════════════════════════════════════════════ #
    #  A08:2025 — SOFTWARE/DATA INTEGRITY FAILURES
    # ════════════════════════════════════════════════ #
    def _a08_integrity_failures(self, resp):
        print("[A08:2025] Integrity Failures...")

        # Already handled in A03 (SRI)
        # Check for insecure deserialization
        deser_headers = [
            "application/x-java-serialized-object",
            "application/x-php-serialized",
        ]
        ct = resp.headers.get("Content-Type", "")
        for dh in deser_headers:
            if dh in ct.lower():
                self._add(
                    "A08:2025",
                    "Software and Data Integrity Failures",
                    "HIGH",
                    "Insecure Deserialization Risk",
                    "Response uses serialization format "
                    "known to be vulnerable to deserialization "
                    "attacks. May lead to RCE.",
                    evidence=f"Content-Type: {ct}",
                    fix=(
                        "Use safe data formats (JSON, XML).\n"
                        "Implement integrity checks on "
                        "serialized objects.\n"
                        "Apply type constraints during "
                        "deserialization."
                    ),
                    cwe="CWE-502",
                    cvss="9.8",
                    sans="SANS #24"
                )

        # Check for unsigned updates or packages
        update_paths = [
            "/update", "/upgrade",
            "/install", "/setup",
            "/api/update",
        ]
        for path in update_paths:
            r = self._get(f"{self.base}{path}")
            if r and r.status_code == 200:
                body = r.text.lower()
                if any(s in body for s in [
                    "update", "install", "download",
                    "package", "version",
                ]):
                    self._add(
                        "A08:2025",
                        "Software and Data Integrity Failures",
                        "MEDIUM",
                        f"Potentially Unsigned Update: {path}",
                        f"Update/install endpoint at {path} "
                        "accessible. May allow installing "
                        "unsigned or malicious packages.",
                        evidence=(
                            f"GET {self.base}{path} → 200"
                        ),
                        fix=(
                            "Require authentication for "
                            "update endpoints.\n"
                            "Sign all software packages.\n"
                            "Verify signatures before install."
                        ),
                        cwe="CWE-494",
                        cvss="6.5"
                    )
                    break

    # ════════════════════════════════════════════════ #
    #  A09:2025 — SECURITY LOGGING FAILURES
    # ════════════════════════════════════════════════ #
    def _a09_logging_failures(self, resp):
        print("[A09:2025] Logging/Monitoring...")

        # Verbose error messages
        error_paths = [
            "/nonexistent_xyz_cybrain_test",
            "/api/nonexistent",
            "/?id=<script>",
            "/error_test_cybrain",
        ]
        verbose_signs = [
            "stack trace", "traceback",
            "at line", "exception in",
            "werkzeug debugger", "django debug",
            "internal error details",
            "file not found at /",
            "no such file or directory",
            "undefined method", "undefined variable",
            "parse error",
        ]
        for path in error_paths:
            r = self._get(f"{self.base}{path}")
            if r and any(
                s in r.text.lower()
                for s in verbose_signs
            ):
                self._add(
                    "A09:2025",
                    "Security Logging and Alerting Failures",
                    "MEDIUM",
                    "Verbose Error Messages",
                    "Application returns detailed error "
                    "messages including stack traces, "
                    "file paths, and internal structure. "
                    "Aids attacker reconnaissance.",
                    evidence=(
                        f"Verbose error at {path}"
                    ),
                    fix=(
                        "Configure custom error pages.\n"
                        "Log errors server-side only.\n"
                        "Never expose stack traces to users.\n"
                        "Use structured logging (ELK/Splunk)."
                    ),
                    cwe="CWE-209",
                    cvss="5.3"
                )
                break

        # Exposed log files
        log_paths = [
            "/logs/access.log",
            "/logs/error.log",
            "/log/app.log",
            "/application.log",
            "/debug.log",
            "/error.log",
            "/storage/logs/laravel.log",
            "/var/log/apache2/access.log",
            "/logs/debug.log",
            "/logs/auth.log",
        ]
        for path in log_paths:
            r = self._get(f"{self.base}{path}")
            if (r and r.status_code == 200 and
                    len(r.text) > 200):
                body = r.text.lower()
                # Verify it's a real log not SPA
                is_spa = any(s in body for s in [
                    "<!doctype html", "<html",
                    "bundle.js", "react", "angular"
                ])
                is_log = any(s in body for s in [
                    "error", "exception", "warning",
                    "info", "debug", "get /",
                    "post /", "http/1",
                    "[error]", "[warn]",
                ])
                if is_log and not is_spa:
                    self._add(
                        "A09:2025",
                        "Security Logging and Alerting Failures",
                        "HIGH",
                        f"Log File Exposed: {path}",
                        f"Log file at {path} is publicly "
                        "accessible. May contain credentials, "
                        "session tokens, API keys, "
                        "and internal paths.",
                        evidence=(
                            f"GET {self.base}{path} → 200 "
                            f"({len(r.text)} bytes)"
                        ),
                        fix=(
                            "Move log files outside web root.\n"
                            "Block via .htaccess:\n"
                            "<Files *.log>\n"
                            "  Require all denied\n"
                            "</Files>"
                        ),
                        cwe="CWE-532",
                        cvss="7.5"
                    )

    # ════════════════════════════════════════════════ #
    #  A10:2025 — MISHANDLING OF EXCEPTIONAL CONDITIONS
    # ════════════════════════════════════════════════ #
    def _a10_mishandling_exceptions(self, resp):
        print("[A10:2025] Exception Handling...")

        # Malformed inputs that trigger exceptions
        exception_tests = [
            ("?id=", "'\";<>{}[]|\\"),
            ("?id=", "9" * 5000),       # Buffer overflow
            ("?id=", "%00"),             # Null byte
            ("?id=", "../../etc/passwd"),# Path traversal
            ("?id=", "NaN"),
            ("?id=", "undefined"),
            ("?id=", "null"),
            ("?id=", "%gg"),             # Invalid URL encoding
        ]
        exception_signs = [
            "exception", "error occurred",
            "unhandled", "fatal error",
            "500 internal server error",
            "application error",
            "null reference", "nullpointerexception",
            "segmentation fault",
            "out of memory",
        ]
        for suffix, payload in exception_tests:
            url = f"{self.target}{suffix}{payload}"
            r = self._get(url)
            if r and r.status_code == 500:
                body = r.text.lower()
                if any(s in body for s in exception_signs):
                    self._add(
                        "A10:2025",
                        "Mishandling of Exceptional Conditions",
                        "MEDIUM",
                        "Unhandled Exception Exposed",
                        "Application returns unhandled exception "
                        "details to users. Reveals internal "
                        "structure and aids targeted attacks.",
                        evidence=(
                            f"Input: {payload[:30]} "
                            f"→ HTTP 500 + exception details"
                        ),
                        fix=(
                            "Implement global exception handlers.\n"
                            "Return generic error messages to users.\n"
                            "Log exceptions server-side only.\n"
                            "Never expose exception details in prod."
                        ),
                        cwe="CWE-755",
                        cvss="5.3"
                    )
                    break

        # SSRF (moved from A10:2021 to here)
        ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254",
            "http://metadata.google.internal",
            "http://[::1]",
            "http://0.0.0.0",
            "http://192.168.1.1",
            "file:///etc/passwd",
        ]
        ssrf_params = [
            "url", "redirect", "proxy", "fetch",
            "src", "href", "load", "target",
            "image", "file", "path", "resource",
            "link", "uri", "addr", "host",
        ]
        ssrf_signs = [
            "root:", "localhost", "127.0.0.1",
            "metadata", "ami-id", "instance-id",
            "ssh-rsa", "169.254",
        ]
        for param in ssrf_params:
            for payload in ssrf_payloads[:4]:
                url = self._build_url(
                    params={param: payload}
                )
                r = self._get(url)
                if r and any(
                    s in r.text.lower()
                    for s in ssrf_signs
                ):
                    self._add(
                        "A10:2025",
                        "Mishandling of Exceptional Conditions",
                        "CRITICAL",
                        "Server-Side Request Forgery (SSRF)",
                        f"SSRF via parameter '{param}'. "
                        "Server making requests to internal "
                        "addresses. Cloud metadata, internal "
                        "APIs accessible.",
                        evidence=(
                            f"?{param}={payload} "
                            "→ internal data in response"
                        ),
                        fix=(
                            "Validate URLs against allowlist.\n"
                            "Block requests to private IP ranges.\n"
                            "Use cloud IMDSv2 with token.\n"
                            "Network-level SSRF controls."
                        ),
                        cwe="CWE-918",
                        cvss="9.8",
                        sans="SANS #25"
                    )
                    return

        # Also test SSRF via POST
        for param in ssrf_params[:6]:
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
                        "A10:2025",
                        "Mishandling of Exceptional Conditions",
                        "CRITICAL",
                        "SSRF via POST Parameter",
                        f"SSRF via POST '{param}'. "
                        "Internal network access confirmed.",
                        evidence=(
                            f"POST {param}={payload} "
                            "→ internal response"
                        ),
                        fix=(
                            "Validate all user-supplied URLs.\n"
                            "Block private IP ranges at network level."
                        ),
                        cwe="CWE-918",
                        cvss="9.8"
                    )
                    return

    # ════════════════════════════════════════════════ #
    #  CWE/SANS EXTRA CHECKS
    # ════════════════════════════════════════════════ #

    def _cwe_path_traversal(self):
        """CWE-22: Path Traversal"""
        print("[CWE-22] Path Traversal...")
        params = [
            "file", "path", "page", "include",
            "template", "view", "doc", "load",
        ]
        traversal_signs = [
            "root:x:", "daemon:", "/bin/bash",
            "/etc/passwd", "windows\\system32",
            "[drivers]", "[fonts]",
        ]
        for payload in PATH_TRAVERSAL:
            for param in params:
                url = self._build_url(
                    params={param: payload}
                )
                r = self._get(url)
                if r and any(
                    s in r.text for s in traversal_signs
                ):
                    self._add(
                        "A05:2025",
                        "Injection",
                        "CRITICAL",
                        "Path Traversal (CWE-22)",
                        f"Path traversal via '{param}'. "
                        "Server file system content returned. "
                        "Full filesystem read access possible.",
                        evidence=(
                            f"?{param}={payload} "
                            "→ /etc/passwd content"
                        ),
                        fix=(
                            "Validate file paths strictly.\n"
                            "Use allowlist of permitted files.\n"
                            "Apply chroot/jail to web process.\n"
                            "Never pass user input to file APIs."
                        ),
                        cwe="CWE-22",
                        cvss="9.1",
                        sans="SANS #6"
                    )
                    return

    def _cwe_xxe(self):
        """CWE-611: XML External Entity"""
        print("[CWE-611] XXE Injection...")
        xml_endpoints = [
            "/api/xml", "/xml", "/upload",
            "/import", "/parse", "/process",
            "/api/import", "/api/parse",
        ]
        xxe_signs = [
            "root:x:", "/bin/bash", "daemon:",
            "etc/passwd",
        ]
        headers = {
            "Content-Type": "application/xml",
            "User-Agent":   BROWSER_UA,
        }
        for path in xml_endpoints:
            r = self._post(
                f"{self.base}{path}",
                data=XXE_PAYLOAD.encode(),
                headers=headers
            )
            if r and r.status_code == 200:
                if any(s in r.text for s in xxe_signs):
                    self._add(
                        "A05:2025",
                        "Injection",
                        "CRITICAL",
                        "XML External Entity (XXE) Injection",
                        f"XXE injection at {path}. Server "
                        "processed malicious XML entity and "
                        "returned file contents. Full filesystem "
                        "read and SSRF possible.",
                        evidence=(
                            f"POST {path} XXE payload "
                            "→ /etc/passwd in response"
                        ),
                        fix=(
                            "Disable external entity processing:\n"
                            "Python lxml: "
                            "etree.XMLParser("
                            "resolve_entities=False)\n"
                            "Java: "
                            "factory.setFeature("
                            "XMLConstants.FEATURE_SECURE_PROCESSING"
                            ", true)\n"
                            "Use JSON instead of XML where possible."
                        ),
                        cwe="CWE-611",
                        cvss="9.8",
                        sans="SANS #4"
                    )
                    return

    def _cwe_open_redirect(self):
        """CWE-601: Open Redirect"""
        print("[CWE-601] Open Redirect...")
        evil = "https://evil-cybrain-test-2025.com"
        redirect_params = [
            "redirect", "url", "next", "goto",
            "return", "return_to", "returnUrl",
            "target", "destination", "forward",
            "continue", "redirect_uri", "callback",
        ]
        for param in redirect_params:
            url = self._build_url(
                params={param: evil}
            )
            r = self._get(url)
            if r and r.url.startswith(evil):
                self._add(
                    "A01:2025",
                    "Broken Access Control",
                    "MEDIUM",
                    "Open Redirect (CWE-601)",
                    f"Parameter '{param}' accepts arbitrary "
                    "external URLs. Attacker can send victims "
                    "a legitimate-looking link that silently "
                    "redirects to phishing or malware sites.",
                    evidence=(
                        f"?{param}={evil} "
                        f"→ redirected to {r.url}"
                    ),
                    fix=(
                        "Validate redirect URLs against allowlist.\n"
                        "Use relative URLs for redirects.\n"
                        "Never redirect to user-supplied URLs.\n"
                        "Use an internal mapping table."
                    ),
                    cwe="CWE-601",
                    cvss="6.1"
                )
                return

    def _cwe_clickjacking(self, resp):
        """CWE-1021: Improper Restriction of Rendered UI"""
        print("[CWE-1021] Clickjacking...")
        xfo = resp.headers.get("X-Frame-Options", "")
        csp = resp.headers.get(
            "Content-Security-Policy", ""
        )
        if not xfo and "frame-ancestors" not in csp:
            self._add(
                "A02:2025",
                "Security Misconfiguration",
                "MEDIUM",
                "Clickjacking Vulnerability (CWE-1021)",
                "Page can be embedded in an iframe on any "
                "external site. Attackers overlay invisible "
                "frames to trick users into clicking "
                "unintended elements (fund transfer, "
                "password change, account deletion).",
                fix=(
                    "Add header: X-Frame-Options: DENY\n"
                    "Or in CSP: "
                    "Content-Security-Policy: "
                    "frame-ancestors 'none'"
                ),
                cwe="CWE-1021",
                cvss="6.1"
            )

    def _cwe_cors_misconfig(self, resp):
        """Additional CORS checks"""
        # Already checked in A02, skip duplicates
        pass

    def _cwe_host_header_injection(self):
        """CWE-20: Host Header Injection"""
        print("[CWE-20] Host Header Injection...")
        try:
            r = self.session.get(
                self.target,
                headers={
                    "User-Agent": BROWSER_UA,
                    "Host": "evil-cybrain-test.com",
                },
                timeout=10,
                verify=False,
                allow_redirects=False
            )
            if r and "evil-cybrain-test.com" in r.text:
                self._add(
                    "A02:2025",
                    "Security Misconfiguration",
                    "HIGH",
                    "Host Header Injection",
                    "Application reflects attacker-controlled "
                    "Host header in response. Can be used for "
                    "password reset poisoning, cache poisoning, "
                    "and SSRF attacks.",
                    evidence=(
                        "Host: evil-cybrain-test.com "
                        "→ reflected in response"
                    ),
                    fix=(
                        "Validate Host header against "
                        "known allowed hosts.\n"
                        "Use explicit server_name in Nginx.\n"
                        "Use ServerName/ServerAlias in Apache."
                    ),
                    cwe="CWE-20",
                    cvss="6.1"
                )
        except Exception:
            pass

    def _cwe_http_methods(self):
        """Check dangerous HTTP methods"""
        print("[CWE-16] HTTP Methods...")
        try:
            r = self.session.options(
                self.target,
                timeout=10,
                verify=False,
                headers={"User-Agent": BROWSER_UA}
            )
            allowed = (
                r.headers.get("Allow", "") +
                r.headers.get("Public", "")
            ).upper()
            dangerous = [
                m for m in
                ["TRACE", "PUT", "DELETE",
                 "CONNECT", "PATCH"]
                if m in allowed
            ]
            if dangerous:
                self._add(
                    "A02:2025",
                    "Security Misconfiguration",
                    "MEDIUM",
                    f"Dangerous HTTP Methods: "
                    f"{', '.join(dangerous)}",
                    f"Methods {', '.join(dangerous)} enabled. "
                    "TRACE → Cross-Site Tracing (XST). "
                    "PUT/DELETE → unauthorized file manipulation.",
                    evidence=(
                        f"OPTIONS → Allow: {allowed}"
                    ),
                    fix=(
                        "Apache:\n"
                        "LimitExcept GET POST {\n"
                        "  Require all denied\n"
                        "}\n"
                        "TraceEnable Off"
                    ),
                    cwe="CWE-16",
                    cvss="5.8"
                )
        except Exception:
            pass

    def _cwe_unrestricted_upload(self):
        """CWE-434: Unrestricted File Upload"""
        print("[CWE-434] File Upload...")
        upload_paths = [
            "/upload", "/api/upload",
            "/file/upload", "/media/upload",
            "/image/upload", "/avatar",
            "/api/files", "/files/upload",
        ]
        for path in upload_paths:
            r = self._get(f"{self.base}{path}")
            if r and r.status_code in [200, 405]:
                # Test uploading a PHP file
                test_data = {
                    "file": (
                        "test.php",
                        b"<?php echo 'cybrain_test'; ?>",
                        "application/x-php"
                    )
                }
                try:
                    r2 = self.session.post(
                        f"{self.base}{path}",
                        files=test_data,
                        timeout=5,
                        verify=False
                    )
                    if r2 and r2.status_code in [
                        200, 201
                    ]:
                        body = r2.text.lower()
                        if any(s in body for s in [
                            "success", "uploaded",
                            "filename", ".php",
                            "url", "path",
                        ]):
                            self._add(
                                "A02:2025",
                                "Security Misconfiguration",
                                "CRITICAL",
                                "Unrestricted File Upload (CWE-434)",
                                f"Upload endpoint {path} accepted "
                                "a .php file without validation. "
                                "Remote code execution possible by "
                                "uploading and accessing a web shell.",
                                evidence=(
                                    f"POST {path} .php file "
                                    f"→ {r2.status_code} accepted"
                                ),
                                fix=(
                                    "Validate file extensions "
                                    "with strict whitelist.\n"
                                    "Check MIME type server-side.\n"
                                    "Store uploads outside web root.\n"
                                    "Rename files on upload.\n"
                                    "Disable script execution in "
                                    "upload directories."
                                ),
                                cwe="CWE-434",
                                cvss="10.0",
                                sans="SANS #12"
                            )
                            return
                except Exception:
                    pass
