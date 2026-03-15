"""
===============================================================
  CYBRAIN - Apache Misconfiguration Detector  (v2.0)
  PFE Master 2 - Information Security
  University of Mohamed Boudiaf, M'sila - Algeria

  CHECKS
  ------
  CA8   ProxyPass inside <Directory> block
  DEP   Deprecated directives (Order, Allow, Deny)
  SYN   Syntax errors (unclosed / mismatched tags)
  MOD   Module dependency issues (mod_ssl, mod_rewrite...)
  SEC   Security hardening rules (22 checks):
        * Directory listing (Indexes)
        * Server signature / token disclosure
        * Weak SSL protocols (SSLv2/3, TLS 1.0/1.1)
        * Weak SSL cipher suites (NULL, EXPORT, RC4...)
        * TRACE method enabled
        * Missing security headers (CSP, HSTS, X-Frame...)
        * LimitRequestBody = 0 (DoS risk)
        * Timeout too large
        * FollowSymLinks without SymLinksIfOwnerMatch
        * Expose PHP version (expose_php = On)
        * AllowOverride All (too permissive)
        * HTTP/2 push proxyPass leak
        * Cleartext passwords in config
        * Open CORS wildcard
        * Missing access log / error log
        * CGI scripts enabled
        * Deprecated mod_php
        * mod_status / mod_info exposed
        * SSLVerifyClient none
        * H2Push On

  FOR EDUCATIONAL / AUTHORIZED TESTING ONLY
===============================================================
"""

import re
import os
import sys
import json

# -- Severity normalisation map ------------------------------------------------
_SEV_NORM = {
    "error":   "CRITICAL", "Error":   "CRITICAL",
    "high":    "HIGH",     "High":    "HIGH",
    "warning": "MEDIUM",   "Warning": "MEDIUM",
    "medium":  "MEDIUM",   "Medium":  "MEDIUM",
    "low":     "LOW",      "Low":     "LOW",
    "info":    "INFO",     "Info":    "INFO",
}


def _norm_sev(raw):
    return _SEV_NORM.get(raw, raw.upper())


class ApacheMisconfigDetector:
    """
    Static analyser for Apache httpd configuration files.
    Works on any .conf file, httpd.conf, apache2.conf, or .htaccess.
    """

    def __init__(self):
        self.misconfigurations = []
        self.files_scanned     = 0
        self._seen             = set()   # dedup (file, line, code)

    # -- Internal helpers ------------------------------------------------------

    def _add(self, file_path, line, code, severity, message):
        """Add a finding, deduplicated by (file, line, code)."""
        key = (file_path, str(line), code)
        if key not in self._seen:
            self._seen.add(key)
            self.misconfigurations.append({
                "file":     file_path,
                "line":     line,
                "code":     code,
                "severity": _norm_sev(severity),
                "message":  message,
            })

    def _find_line(self, content, pattern):
        """Return 1-based line number of first regex match, or '-'."""
        try:
            m = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
            if m:
                return content[:m.start()].count("\n") + 1
        except Exception:
            pass
        return "-"

    # -- Public scan API -------------------------------------------------------

    def scan_content(self, content, source_name="Input"):
        """Scan a string of Apache config content."""
        self.files_scanned += 1
        lines = content.splitlines()
        self._check_ca8_proxypass_in_directory(source_name, content, lines)
        self._check_deprecated_directives(source_name, content, lines)
        self._check_syntax_errors(source_name, content, lines)
        self._check_module_dependencies(source_name, content, lines)
        self._check_security_hardening(source_name, content, lines)

    def scan_file(self, file_path):
        """Scan a single Apache config file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
            self.scan_content(content, file_path)
        except Exception as e:
            print("[ERROR] Cannot read {}: {}".format(file_path, e))

    def scan_directory(self, directory_path):
        """Recursively scan all Apache config files in a directory."""
        for root, _, files in os.walk(directory_path):
            for fname in files:
                if (fname.endswith(".conf") or
                        fname == ".htaccess" or
                        fname.startswith("httpd") or
                        fname.startswith("apache2")):
                    self.scan_file(os.path.join(root, fname))

    # -- CA8: ProxyPass inside <Directory> ------------------------------------
    def _check_ca8_proxypass_in_directory(self, fp, content, lines):
        dir_re   = re.compile(r"<Directory\s+[^>]+>(.*?)</Directory>",
                               re.DOTALL | re.IGNORECASE)
        proxy_re = re.compile(r"^\s*ProxyPass\s+", re.MULTILINE | re.IGNORECASE)
        for m in dir_re.finditer(content):
            if proxy_re.search(m.group(1)):
                line = content[:m.start()].count("\n") + 1
                self._add(fp, line, "CA8", "Error",
                          "ProxyPass directive cannot occur within a "
                          "<Directory> section. Move it to a <Location> "
                          "or <VirtualHost> context.")

    # -- Deprecated directives (Apache 2.4) -----------------------------------
    def _check_deprecated_directives(self, fp, content, lines):
        deprecated = {
            "Order":   "Use 'Require all granted/denied' instead.",
            "Allow":   "Use 'Require' directive (mod_authz_core).",
            "Deny":    "Use 'Require' directive (mod_authz_core).",
            "Satisfy": "Removed in Apache 2.4. Use <RequireAll>/<RequireAny>.",
        }
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for kw, note in deprecated.items():
                if re.match(r"^" + kw + r"\s+", stripped, re.IGNORECASE):
                    self._add(fp, i, "DEPRECATED", "Warning",
                              "Directive '{}' is deprecated in Apache 2.4. {}".format(kw, note))

    # -- Syntax errors ---------------------------------------------------------
    def _check_syntax_errors(self, fp, content, lines):
        open_tags = []
        tag_re = re.compile(r"^\s*<(/?)(\w+)([^>]*)>", re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            if line.strip().startswith("#"):
                continue
            m = tag_re.match(line)
            if not m:
                continue
            is_close = m.group(1) == "/"
            tag_name = m.group(2)
            if not is_close:
                if not line.strip().endswith("/>"):
                    open_tags.append((tag_name, i))
            else:
                if not open_tags:
                    self._add(fp, i, "SYNTAX", "Error",
                              "Unexpected closing tag </{}>  "
                              "with no matching opening tag.".format(tag_name))
                else:
                    last, last_line = open_tags.pop()
                    if last.lower() != tag_name.lower():
                        self._add(fp, i, "SYNTAX", "Error",
                                  "Mismatched tag: found </{}>, "
                                  "expected </{}> (opened at line {}).".format(
                                      tag_name, last, last_line))
        for tag_name, line_num in open_tags:
            self._add(fp, line_num, "SYNTAX", "Error",
                      "Unclosed tag <{}>.".format(tag_name))

    # -- Module dependency checks ----------------------------------------------
    def _check_module_dependencies(self, fp, content, lines):
        deps = [
            ("SSLEngine On",      "mod_ssl",        "LoadModule ssl_module"),
            ("RewriteEngine On",  "mod_rewrite",    "LoadModule rewrite_module"),
            ("ProxyPass",         "mod_proxy",      "LoadModule proxy_module"),
            ("Header always set", "mod_headers",    "LoadModule headers_module"),
            ("AuthType Basic",    "mod_auth_basic", "LoadModule auth_basic_module"),
        ]
        for directive, module, load_str in deps:
            if directive.lower() in content.lower():
                if load_str.lower() not in content.lower():
                    line = self._find_line(content, re.escape(directive))
                    self._add(fp, line, "MODULE_MISSING", "Error",
                              "'{}' requires {} but '{}' was not found in this config.".format(
                                  directive, module, load_str))

    # -- Security hardening (22 rules) ----------------------------------------
    def _check_security_hardening(self, fp, content, lines):
        is_main = any(
            k in fp.lower()
            for k in ("httpd.conf", "apache2.conf", "000-default")
        )

        # 1. Directory listing
        if (re.search(r"^\s*Options\s+[^#]*\bIndexes\b",
                       content, re.MULTILINE | re.IGNORECASE) and
                not re.search(r"^\s*Options\s+[^#]*-Indexes",
                               content, re.MULTILINE | re.IGNORECASE)):
            ln = self._find_line(content, r"Options\s+.*Indexes")
            self._add(fp, ln, "DIR_LISTING", "High",
                      "Directory listing (Indexes) is enabled. "
                      "Attackers can enumerate all files. Fix: Options -Indexes")

        # 2. Server signature / version disclosure
        if re.search(r"^\s*ServerSignature\s+On",
                      content, re.MULTILINE | re.IGNORECASE):
            ln = self._find_line(content, r"ServerSignature\s+On")
            self._add(fp, ln, "INFO_DISCLOSURE", "Medium",
                      "ServerSignature On reveals Apache version in error pages. "
                      "Fix: ServerSignature Off")

        if re.search(r"^\s*ServerTokens\s+(?!Prod|Minimal)",
                      content, re.MULTILINE | re.IGNORECASE):
            ln = self._find_line(content, r"ServerTokens\s+")
            self._add(fp, ln, "INFO_DISCLOSURE", "Medium",
                      "ServerTokens exposes detailed version info. "
                      "Fix: ServerTokens Prod")

        # 3. Weak SSL protocols
        if re.search(r"^\s*SSLProtocol\s+.*(SSLv2|SSLv3|TLSv1\b|TLSv1\.1)",
                      content, re.MULTILINE | re.IGNORECASE):
            ln = self._find_line(content, r"SSLProtocol")
            self._add(fp, ln, "SSL_WEAK_PROTOCOL", "High",
                      "Weak SSL/TLS protocols (SSLv2, SSLv3, TLS 1.0/1.1) enabled. "
                      "Vulnerable to POODLE, BEAST, DROWN. "
                      "Fix: SSLProtocol -all +TLSv1.2 +TLSv1.3")

        # 4. Weak cipher suites
        if re.search(r"^\s*SSLCipherSuite\s+.*(NULL|EXPORT|RC4|MD5|DES\b|3DES|aNULL)",
                      content, re.MULTILINE | re.IGNORECASE):
            ln = self._find_line(content, r"SSLCipherSuite")
            self._add(fp, ln, "SSL_WEAK_CIPHER", "High",
                      "Weak SSL ciphers (NULL, EXPORT, RC4, MD5, DES) enabled. "
                      "Fix: SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:"
                      "ECDHE-RSA-AES128-GCM-SHA256:!aNULL:!EXPORT:!RC4")

        # 5. TRACE method
        if re.search(r"^\s*TraceEnable\s+On",
                      content, re.MULTILINE | re.IGNORECASE):
            ln = self._find_line(content, r"TraceEnable\s+On")
            self._add(fp, ln, "TRACE_ENABLED", "Medium",
                      "TraceEnable On allows HTTP TRACE method. "
                      "Vulnerable to Cross-Site Tracing (XST). Fix: TraceEnable Off")
        elif is_main and "TraceEnable" not in content:
            self._add(fp, "-", "TRACE_ENABLED", "Medium",
                      "TraceEnable is not explicitly disabled. "
                      "Default may allow TRACE. Fix: TraceEnable Off")

        # 6. Missing security headers
        required_headers = {
            "Content-Security-Policy":   ("MISSING_HEADER", "High",
                "Prevents XSS and data injection attacks."),
            "X-Frame-Options":           ("MISSING_HEADER", "High",
                "Prevents clickjacking attacks."),
            "X-Content-Type-Options":    ("MISSING_HEADER", "Medium",
                "Prevents MIME-type sniffing."),
            "Strict-Transport-Security": ("MISSING_HEADER", "High",
                "Forces HTTPS - prevents SSL stripping."),
            "Referrer-Policy":           ("MISSING_HEADER", "Low",
                "Controls referrer information leakage."),
        }
        for header, (code, sev, desc) in required_headers.items():
            if ("Header always set " + header not in content and
                    "Header set " + header not in content):
                if is_main or ".htaccess" in fp.lower():
                    self._add(fp, "-", code, sev,
                              "Security header '{}' is not configured. {} "
                              "Fix: Header always set {} \"<value>\"".format(
                                  header, desc, header))

        # 7. LimitRequestBody = 0
        if re.search(r"^\s*LimitRequestBody\s+0\b",
                      content, re.MULTILINE | re.IGNORECASE):
            ln = self._find_line(content, r"LimitRequestBody\s+0")
            self._add(fp, ln, "DOS_RISK", "Medium",
                      "LimitRequestBody 0 allows unlimited upload size. "
                      "Risk of DoS via large requests. "
                      "Fix: LimitRequestBody 10485760  (10MB)")

        # 8. Timeout too large
        tm = re.search(r"^\s*Timeout\s+(\d+)",
                        content, re.MULTILINE | re.IGNORECASE)
        if tm:
            if int(tm.group(1)) > 300:
                ln = self._find_line(content, r"Timeout\s+")
                self._add(fp, ln, "DOS_RISK", "Low",
                          "Timeout is {}s - larger than 300s. "
                          "Slowloris DoS attack risk. Fix: Timeout 60".format(tm.group(1)))
        elif is_main:
            self._add(fp, "-", "DOS_RISK", "Low",
                      "Timeout directive not set. Default (300s) may be too high. "
                      "Fix: Timeout 60")

        # 9. FollowSymLinks without SymLinksIfOwnerMatch
        if (re.search(r"^\s*Options\s+[^#]*\bFollowSymLinks\b",
                       content, re.MULTILINE | re.IGNORECASE) and
                not re.search(r"SymLinksIfOwnerMatch",
                               content, re.IGNORECASE)):
            ln = self._find_line(content, r"FollowSymLinks")
            self._add(fp, ln, "SYMLINK_RISK", "High",
                      "FollowSymLinks without SymLinksIfOwnerMatch allows "
                      "symlink attacks to escape the document root. "
                      "Fix: Options -FollowSymLinks +SymLinksIfOwnerMatch")

        # 10. AllowOverride All
        if re.search(r"^\s*AllowOverride\s+All\b",
                      content, re.MULTILINE | re.IGNORECASE):
            ln = self._find_line(content, r"AllowOverride\s+All")
            self._add(fp, ln, "HARDENING", "Medium",
                      "AllowOverride All allows .htaccess to override any setting. "
                      "Fix: AllowOverride None  or  AllowOverride AuthConfig Limit")

        # 11. Cleartext password in config
        if re.search(r"(password|passwd|secret)\s*=\s*['\"][^'\"]{4,}['\"]",
                      content, re.IGNORECASE):
            ln = self._find_line(content, r"password\s*=")
            self._add(fp, ln, "HARDCODED_CRED", "Critical",
                      "Cleartext password detected in Apache config. "
                      "Use environment variables or secure credential stores.")

        # 12. AuthUserFile pointing to obvious path
        if re.search(r"AuthUserFile\s+.*(htpasswd|\.htpasswd)",
                      content, re.IGNORECASE):
            ln = self._find_line(content, r"AuthUserFile")
            self._add(fp, ln, "HARDENING", "Warning",
                      "AuthUserFile detected. Ensure the .htpasswd file is "
                      "outside the document root and uses strong hashed passwords.")

        # 13. CORS wildcard
        if re.search(r"Header\s+(always\s+)?set\s+Access-Control-Allow-Origin\s+['\"]?\*",
                      content, re.IGNORECASE):
            ln = self._find_line(content, r"Access-Control-Allow-Origin")
            self._add(fp, ln, "CORS_WILDCARD", "Medium",
                      "CORS wildcard 'Access-Control-Allow-Origin: *' allows "
                      "any website to read API responses. "
                      "Restrict to specific trusted origins.")

        # 14. mod_status exposed publicly
        if (re.search(r"SetHandler\s+server-status", content, re.IGNORECASE) and
                not re.search(r"Require\s+(ip|host|local)", content, re.IGNORECASE)):
            ln = self._find_line(content, r"server-status")
            self._add(fp, ln, "INFO_DISCLOSURE", "High",
                      "mod_status (server-status) is enabled without IP restriction. "
                      "Server internals exposed to anyone. "
                      "Fix: Add 'Require ip 127.0.0.1'")

        # 15. mod_info exposed publicly
        if re.search(r"SetHandler\s+server-info", content, re.IGNORECASE):
            ln = self._find_line(content, r"server-info")
            self._add(fp, ln, "INFO_DISCLOSURE", "High",
                      "mod_info (server-info) is enabled. Full config exposed. "
                      "Disable or restrict to localhost only.")

        # 16. CGI scripts enabled
        if re.search(r"AddHandler\s+cgi-script|Options\s+.*\bExecCGI\b",
                      content, re.IGNORECASE):
            ln = self._find_line(content, r"ExecCGI|cgi-script")
            self._add(fp, ln, "HARDENING", "Medium",
                      "CGI script execution is enabled. CGI scripts are a "
                      "common RCE vector. Disable if not required: Options -ExecCGI")

        # 17. Expose PHP version
        if re.search(r"expose_php\s*=\s*On", content, re.IGNORECASE):
            ln = self._find_line(content, r"expose_php")
            self._add(fp, ln, "INFO_DISCLOSURE", "Low",
                      "expose_php = On reveals PHP version in headers. "
                      "Fix: expose_php = Off in php.ini")

        # 18. Missing access log
        if is_main and not re.search(r"^\s*CustomLog\s+",
                                      content, re.MULTILINE | re.IGNORECASE):
            self._add(fp, "-", "LOGGING", "Medium",
                      "No CustomLog directive found. Access logging is not configured. "
                      "Fix: CustomLog /var/log/apache2/access.log combined")

        # 19. Missing error log
        if is_main and not re.search(r"^\s*ErrorLog\s+",
                                      content, re.MULTILINE | re.IGNORECASE):
            self._add(fp, "-", "LOGGING", "Medium",
                      "No ErrorLog directive found. Error logging not configured. "
                      "Fix: ErrorLog /var/log/apache2/error.log")

        # 20. Deprecated mod_php
        if re.search(r"AddType\s+application/x-httpd-php",
                      content, re.IGNORECASE):
            ln = self._find_line(content, r"x-httpd-php")
            self._add(fp, ln, "DEPRECATED", "Low",
                      "mod_php via AddType is deprecated. "
                      "Use PHP-FPM with mod_proxy_fcgi for better isolation.")

        # 21. SSLVerifyClient none
        if re.search(r"^\s*SSLVerifyClient\s+none",
                      content, re.MULTILINE | re.IGNORECASE):
            ln = self._find_line(content, r"SSLVerifyClient")
            self._add(fp, ln, "HARDENING", "Low",
                      "SSLVerifyClient none - no client certificate verification. "
                      "Consider requiring client certs for sensitive endpoints.")

        # 22. HTTP/2 Push enabled
        if re.search(r"H2Push\s+On", content, re.IGNORECASE):
            ln = self._find_line(content, r"H2Push")
            self._add(fp, ln, "HARDENING", "Low",
                      "HTTP/2 Server Push (H2Push On) is enabled. "
                      "Can leak sensitive headers. Disable if not actively used.")

    # -- Results API -----------------------------------------------------------

    def get_results(self):
        return self.misconfigurations

    def get_results_json(self):
        return json.dumps(self.misconfigurations, indent=2)

    def generate_report(self):
        """Print human-readable report to console."""
        print("\n[CYBRAIN APACHE] Scanned {} file(s). {} issue(s) found.\n".format(
            self.files_scanned, len(self.misconfigurations)))

        if not self.misconfigurations:
            print("[+] No misconfigurations detected.")
            return

        print("=" * 60)
        sorted_issues = sorted(
            self.misconfigurations,
            key=lambda x: (x["file"], 0 if x["line"] == "-" else x["line"])
        )
        current_file = None
        counts = {}
        for issue in sorted_issues:
            sev = issue["severity"]
            counts[sev] = counts.get(sev, 0) + 1
            if issue["file"] != current_file:
                current_file = issue["file"]
                print("\nFile: {}".format(current_file))
                print("-" * 40)
            print("  [{}] [{}] {}: {}".format(
                issue["line"], issue["severity"],
                issue["code"], issue["message"]))

        print("\n" + "=" * 60)
        print("Summary:")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if counts.get(sev):
                print("  {}: {}".format(sev, counts[sev]))


# -- CLI entry point -----------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python detect_apache_misconf.py <file_or_directory> [--json]")
        sys.exit(1)

    target_path = sys.argv[1]
    output_json = "--json" in sys.argv

    detector = ApacheMisconfigDetector()

    if os.path.isfile(target_path):
        detector.scan_file(target_path)
    elif os.path.isdir(target_path):
        detector.scan_directory(target_path)
    else:
        print("Error: {} is not a valid file or directory.".format(target_path))
        sys.exit(1)

    if output_json:
        print(detector.get_results_json())
    else:
        detector.generate_report()
