import requests
import re
import json
import time
import os
import csv
import traceback
from urllib.parse import urlparse, urlunparse, urlencode, parse_qs
import urllib3

# Disable SSL warnings for scanning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class UrlScanner:
    def __init__(self, target_url):
        self.target_url = target_url.strip()
        # Add http:// if missing
        if not self.target_url.startswith(('http://', 'https://')):
            self.target_url = 'http://' + self.target_url
        
        # Strip fragment (#) which causes issues with requests
        self.target_url = self.target_url.split('#')[0].rstrip('/')
        
        self.results = []
        self.timeout = 20 # Increased timeout for slow targets
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        
        # Reports directory
        self.report_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "report")
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

    def _add(self, severity, title, code, message, fix="", cwe="", owasp="", evidence="", cvss=""):
        self.results.append({
            "severity": severity,
            "title": title,
            "code": code,
            "message": message,
            "fix": fix,
            "cwe": cwe,
            "owasp": owasp,
            "evidence": evidence,
            "cvss": cvss,
            "file": self.target_url
        })

    def _get(self, url, **kwargs):
        try:
            return self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True, **kwargs)
        except Exception as e:
            print(f"[GET ERROR] {url}: {str(e)}")
            return None

    def scan(self):
        print(f"[SCANNER] Starting scan on {self.target_url}...")
        
        # Step 1: Connectivity Check
        resp = self._get(self.target_url)
        if resp is None:
            # Retry with www.
            if "://www." not in self.target_url:
                alt_url = self.target_url.replace("://", "://www.")
                print(f"[SCANNER] Retrying with www: {alt_url}")
                resp = self._get(alt_url)
                if resp: self.target_url = alt_url
            
        if resp is None:
            self._add("HIGH", "Connection Error", "CONN_FAIL", 
                      "Could not reach target. Verify URL or check network connectivity.", 
                      fix="Try disabling firewalls or checking proxy settings.")
            self.generate_reports()
            return self.results

        print(f"[SCANNER] Connected! Status: {resp.status_code}")

        # --- PHASE 1: PASSIVE SCANNING ---
        self._check_security_headers(resp)
        self._check_cookies(resp)
        self._check_server_exposure(resp)
        self._check_https_info(resp)
        self._check_cors_policy(resp)

        # --- PHASE 2: ACTIVE SCANNING ---
        self._check_sensitive_paths()
        self._check_active_vulns(resp)
        self._check_http_methods()
        self._check_csrf_vulnerabilities(resp)
        self._check_jwt_vulnerabilities(resp)
        self._check_idor_vulnerabilities(resp)
        self._check_xxe_vulnerabilities(resp)
        
        # Step 3: Finalize
        self.generate_reports()
        return self.results

    def _check_security_headers(self, resp):
        h = resp.headers
        checks = {
            "Content-Security-Policy": ("HIGH", "CWE-693", "A05:2021", "Missing CSP allows XSS."),
            "X-Frame-Options": ("MEDIUM", "CWE-1021", "A05:2021", "Missing X-Frame-Options enables clickjacking."),
            "X-Content-Type-Options": ("MEDIUM", "CWE-693", "A05:2021", "Missing nosniff header allows MIME sniffing."),
            "Strict-Transport-Security": ("HIGH", "CWE-319", "A02:2021", "Missing HSTS allows MITM attacks."),
            "Referrer-Policy": ("LOW", "CWE-200", "A01:2021", "Referrer-Policy header missing."),
            "Permissions-Policy": ("LOW", "CWE-200", "A01:2021", "Permissions-Policy header missing.")
        }
        missing = [header for header in checks if header not in h]
        if missing:
            self._add("HIGH", "Missing Security Headers", "SEC_HEADERS",
                      f"Critical missing headers: {', '.join(missing)}",
                      fix="Configure the web server to send these security headers.",
                      cwe="CWE-693", owasp="A05:2021")

    def _check_cookies(self, resp):
        for cookie in self.session.cookies:
            flags = []
            if not getattr(cookie, 'secure', False): flags.append("Secure")
            if not getattr(cookie, 'httponly', False): flags.append("HttpOnly")
            if flags:
                self._add("MEDIUM", f"Insecure Cookie Flags: {cookie.name}", "COOKIE_FLAGS",
                          f"Cookie '{cookie.name}' missing flags: {', '.join(flags)}.",
                          fix="Enable Secure and HttpOnly flags on all sensitive cookies.",
                          cwe="CWE-614", owasp="A05:2021")

    def _check_server_exposure(self, resp):
        server = resp.headers.get("Server")
        powered_by = resp.headers.get("X-Powered-By")
        if server:
            self._add("LOW", "Server Banner Disclosure", "SERVER_INFO",
                      f"Server header reveals: {server}",
                      fix="Modify configuration to hide the Server banner.",
                      cwe="CWE-200")
        if powered_by:
            self._add("LOW", "X-Powered-By Disclosure", "TECH_INFO",
                      f"Revealed backend tech: {powered_by}",
                      fix="Disable X-Powered-By header in application settings.",
                      cwe="CWE-200")

    def _check_https_info(self, resp):
        if not self.target_url.startswith('https://'):
            self._add("HIGH", "Insecure HTTP Protocol", "NO_HTTPS",
                      "Site uses HTTP instead of HTTPS. All traffic is sent in plaintext.",
                      fix="Install an SSL certificate and enforce HTTPS.",
                      cwe="CWE-319", owasp="A02:2021")

    def _check_cors_policy(self, resp):
        cors = resp.headers.get("Access-Control-Allow-Origin")
        if cors == "*":
            self._add("MEDIUM", "Permissive CORS Policy", "CORS_ANY",
                      "Access-Control-Allow-Origin is set to '*'.",
                      fix="Restrict CORS access to specific trusted domains.",
                      cwe="CWE-942", owasp="A05:2021")

    def _check_sensitive_paths(self):
        paths = [
            ("/.env", "Environment config", "CRITICAL", "CWE-538"),
            ("/.git/", "Git history", "CRITICAL", "CWE-538"),
            ("/phpinfo.php", "PHP configuration", "HIGH", "CWE-200"),
            ("/config.php.bak", "Database credentials backup", "CRITICAL", "CWE-538"),
            ("/server-status", "Apache server status", "MEDIUM", "CWE-200"),
            ("/.ssh/id_rsa", "SSH Private Key", "CRITICAL", "CWE-538"),
            ("/wp-config.php.save", "WordPress config backup", "CRITICAL", "CWE-538"),
            ("/dump.sql", "Database Dump", "CRITICAL", "CWE-538"),
            ("/backup.zip", "Full Backup Archive", "CRITICAL", "CWE-538")
        ]
        for path, name, sev, cwe in paths:
            t_url = self.target_url.rstrip('/') + path
            r = self._get(t_url)
            if r and r.status_code == 200 and len(r.text) > 0:
                self._add(sev, f"Sensitive File Exposed: {path}", "FILES_EXPOSED",
                          f"Exposed {name} found at {path}.",
                          fix="Remove this file from the web root.",
                          cwe=cwe, owasp="A05:2021", evidence=f"GET {t_url} -> 200 OK")

    def _check_active_vulns(self, resp):
        # SQL Injection
        payloads = ["1' OR '1'='1", "1' ORDER BY 1--", "') OR ('1'='1"]
        for p in payloads:
            test_url = f"{self.target_url}?id={p}"
            r = self._get(test_url)
            if r and any(err in r.text.lower() for err in ["sql syntax", "mysql_fetch", "ora-", "sqlite"]):
                self._add("CRITICAL", "SQL Injection Detected", "SQLI",
                          f"Reflected database error found testing {p}.",
                          fix="Use prepared statements and parameterized queries.",
                          cwe="CWE-89", owasp="A03:2021", evidence=f"Error string in {test_url}")
                break

        # XSS
        payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        for p in payloads:
            test_url = f"{self.target_url}?q={p}"
            r = self._get(test_url)
            if r and p in r.text:
                self._add("HIGH", "Reflected XSS Detected", "XSS",
                          f"Input script {p} reflected on page.",
                          fix="Encode all user-supplied output for HTML context.",
                          cwe="CWE-79", owasp="A03:2021", evidence=f"Script found in {test_url}")
                break

    def _check_http_methods(self):
        try:
            r = self.session.options(self.target_url, timeout=5, verify=False)
            allow = r.headers.get("Allow", "")
            dangerous = [m for m in ["TRACE", "PUT", "DELETE", "CONNECT"] if m in allow]
            if dangerous:
                self._add("MEDIUM", "Dangerous HTTP Methods Enabled", "HTTP_METHODS",
                          f"Methods {', '.join(dangerous)} are enabled.",
                          fix="Disable unnecessary HTTP methods in web server config.",
                          cwe="CWE-201")
        except: pass

    def _check_csrf_vulnerabilities(self, resp):
        if "<form" in resp.text and "csrf" not in resp.text.lower():
            self._add("HIGH", "Potential CSRF Vulnerability", "NO_CSRF_TOKEN",
                      "HTML forms detected without obvious anti-CSRF tokens.",
                      fix="Implement synchronizer token pattern or use SameSite=Strict cookies.",
                      cwe="CWE-352", owasp="A01:2021")

    def _check_jwt_vulnerabilities(self, resp):
        # Heuristic: look for JWT-like strings in headers or cookies
        tokens = []
        auth = resp.headers.get("Authorization", "")
        if auth.startswith("Bearer "): tokens.append(auth.split(" ")[1])
        for cookie in self.session.cookies:
            if re.match(r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$', cookie.value):
                tokens.append(cookie.value)
        
        for t in tokens:
            try:
                # Weakness: alg=none (check header base64)
                header_b64 = t.split('.')[0]
                # Pad for base64 decode
                header_json = str(requests.utils.base64.b64decode(header_b64 + '=='))
                if '"alg":"none"' in header_json.lower():
                    self._add("CRITICAL", "JWT 'alg:none' Vulnerability", "JWT_NONE",
                              "JWT token allows 'none' algorithm which bypasses signature verification.",
                              fix="Ensure the JWT library enforces strict algorithm validation.",
                              cwe="CWE-347", owasp="A07:2021")
            except: pass

    def _check_idor_vulnerabilities(self, resp):
        # Test for sequential IDs in URL
        id_match = re.search(r'[\?\&](\w+i[dD])=(\d+)', self.target_url)
        if id_match:
            param = id_match.group(1)
            val = int(id_match.group(2))
            test_url = self.target_url.replace(f"{param}={val}", f"{param}={val+1}")
            r = self._get(test_url)
            if r and r.status_code == 200 and len(r.text) > 0:
                 self._add("HIGH", "Potential IDOR Vulnerability", "IDOR",
                           f"Possible IDOR found by incrementing parameter '{param}'.",
                           fix="Implement object-level access controls.",
                           cwe="CWE-639", owasp="A01:2021")

    def _check_xxe_vulnerabilities(self, resp):
        # Attempt simple XXE injection if XML content is detected
        if "application/xml" in resp.headers.get("Content-Type", "").lower() or "<?xml" in resp.text[:100]:
             self._add("HIGH", "Potential XXE Vulnerability", "XXE_SUSPECT",
                       "Target appears to handle XML. Risk of XML External Entity injection.",
                       fix="Disable DTD and External Entity processing in XML parsers.",
                       cwe="CWE-611", owasp="A05:2021")

    def generate_reports(self):
        # Markdown Report
        md_path = os.path.join(self.report_dir, "vulnerability_report.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write("# Web Application Vulnerability Assessment Report\n\n")
            f.write(f"**Target URL:** `{self.target_url}`\n\n")
            f.write(f"**Scan Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Overall Risk:** **{self._calc_overall_risk()}**\n\n---\n\n")
            
            f.write("## Detailed Findings\n\n")
            for i, res in enumerate(self.results, 1):
                f.write(f"### [{i}] {res['title']}\n")
                f.write(f"- **Severity:** {res['severity']}\n")
                f.write(f"- **CWE:** {res['cwe']}\n")
                f.write(f"- **OWASP:** {res['owasp']}\n\n")
                f.write(f"**Description:**\n{res['message']}\n\n")
                if res['evidence']: f.write(f"**Evidence:**\n`{res['evidence']}`\n\n")
                f.write(f"**Fix Recommendation:**\n{res['fix']}\n\n---\n\n")

        # CSV Summary
        csv_path = os.path.join(self.report_dir, "findings_summary.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["severity", "title", "code", "message", "fix", "cwe", "owasp", "evidence", "cvss", "file"])
            writer.writeheader()
            for res in self.results:
                writer.writerow(res)

    def _calc_overall_risk(self):
        sevs = [r['severity'] for r in self.results]
        if "CRITICAL" in sevs: return "CRITICAL"
        if "HIGH" in sevs: return "HIGH"
        if "MEDIUM" in sevs: return "MEDIUM"
        return "LOW"

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
    scanner = UrlScanner(target)
    scanner.scan()
    print(f"Scan complete. Found {len(scanner.results)} issues.")
