"""
===============================================================
  CYBRAIN - AI Security Analysis Engine  (v2.0)
  Gemini 2.0 Flash + Pure Python Offline Fallback
  PFE Master 2 - Information Security
  University of Mohamed Boudiaf, M'sila - Algeria

  MODES
  -----
  Online  : Gemini 2.0 Flash via google-generativeai
  Offline : Full rule-based engine (zero quota, works always)

  FOR EDUCATIONAL / AUTHORIZED TESTING ONLY
===============================================================
"""

import os
import re
import json
from datetime import datetime

import requests
from dotenv import load_dotenv

load_dotenv()

_OPENROUTER_KEY = os.environ.get("OPENROUTER_API_KEY", "")

try:
    import google.generativeai as genai
    _API_KEY = os.environ.get("GEMINI_API_KEY", "")
    if _API_KEY:
        genai.configure(api_key=_API_KEY)
    _GENAI_AVAILABLE = bool(_API_KEY)
except Exception as e:
    _GENAI_AVAILABLE = False
    print(f"[ENGINE] AI initialization failed: {e}")

CVE_DATABASE = {
    "SQL Injection": {
        "cve": "CVE-2023-23397", "cwe": "CWE-89", "cvss": "9.8",
        "owasp": "A05:2025 Injection",
        "attack": "Attacker injects OR 1=1 - auth bypassed.",
        "fix_cmd": (
            "Python: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))\n"
            "PHP:    $stmt = $pdo->prepare('SELECT * FROM users WHERE id=?');\n"
            "        $stmt->execute([$id]);"
        ),
    },
    "XSS": {
        "cve": "CVE-2023-1829", "cwe": "CWE-79", "cvss": "7.4",
        "owasp": "A05:2025 Injection",
        "attack": "Script injected. Session cookie stolen.",
        "fix_cmd": (
            "Python: from markupsafe import escape; safe = escape(user_input)\n"
            "JS:     element.textContent = input  (NOT innerHTML)\n"
            "PHP:    echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8')"
        ),
    },
    "Hardcoded Credentials": {
        "cve": "CWE-798", "cwe": "CWE-798", "cvss": "9.1",
        "owasp": "A07:2025 Authentication Failures",
        "attack": "Credentials committed to GitHub. Full data breach.",
        "fix_cmd": (
            "Python: import os; pwd = os.environ.get('DB_PASSWORD')\n"
            "JS:     const pwd = process.env.DB_PASSWORD\n"
            "Add .env to .gitignore - NEVER commit it"
        ),
    },
    "Command Injection": {
        "cve": "CVE-2023-44487", "cwe": "CWE-78", "cvss": "10.0",
        "owasp": "A05:2025 Injection",
        "attack": "User input passed to shell. System compromised.",
        "fix_cmd": (
            "Python: subprocess.run(['ping', '-c', '1', host], shell=False)\n"
            "Never use os.system() or shell=True with user input"
        ),
    },
    "Path Traversal": {
        "cve": "CVE-2021-41773", "cwe": "CWE-22", "cvss": "9.1",
        "owasp": "A05:2025 Injection",
        "attack": "../../etc/passwd read via file parameter.",
        "fix_cmd": (
            "Python: safe = os.path.basename(user_input)\n"
            "        real = os.path.realpath(os.path.join(base, safe))\n"
            "        assert real.startswith(base)"
        ),
    },
    "Weak Cryptography": {
        "cve": "CVE-2023-2650", "cwe": "CWE-327", "cvss": "6.5",
        "owasp": "A04:2025 Cryptographic Failures",
        "attack": "MD5 hash cracked with rainbow table in seconds.",
        "fix_cmd": (
            "Python: import bcrypt\n"
            "        hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())"
        ),
    },
    "Missing HTTP Security Headers": {
        "cve": "CWE-693", "cwe": "CWE-693", "cvss": "6.5",
        "owasp": "A02:2025 Security Misconfiguration",
        "attack": "No X-Frame-Options enables clickjacking.",
        "fix_cmd": (
            "Header always set X-Frame-Options DENY\n"
            "Header always set X-Content-Type-Options nosniff\n"
            "Header always set Strict-Transport-Security max-age=31536000"
        ),
    },
    "Unencrypted HTTP": {
        "cve": "CWE-319", "cwe": "CWE-319", "cvss": "7.5",
        "owasp": "A04:2025 Cryptographic Failures",
        "attack": "Wireshark captures plaintext credentials on public WiFi.",
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
        "attack": "DEBUG=True exposes Werkzeug interactive console.",
        "fix_cmd": (
            "Python: DEBUG = os.environ.get('DEBUG','False') == 'True'\n"
            "Flask:  app.run(debug=False)"
        ),
    },
}

SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}

CODE_FIX_TEMPLATES = {
    "SQL Injection": {
        "py": [
            (r'cursor\.execute\(([^,\)]+)\+([^)]+)\)',
             r'cursor.execute(\1, (\2,))'),
        ],
    },
    "Debug Mode": {
        "py": [
            (r'\bDEBUG\s*=\s*True\b',
             "DEBUG = os.environ.get('DEBUG', 'False') == 'True'"),
            (r'app\.run\s*\((.*?)debug\s*=\s*True(.*?)\)',
             r'app.run(\1debug=False\2)'),
        ],
    },
    "Hardcoded Credentials": {
        "py": [
            (r'(password|passwd|secret|api_key|apikey)\s*=\s*["\'][^"\']{4,}["\']',
             r'# CYBRAIN FIX: use os.environ.get("CREDENTIAL_NAME")'),
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
}

APACHE_FIXES = [
    (r'Order\s+allow,deny',                 'Require all granted'),
    (r'Order\s+deny,allow',                 'Require all denied'),
    (r'Allow\s+from\s+all',                 '# Replaced: Require all granted'),
    (r'Deny\s+from\s+all',                  '# Replaced: Require all denied'),
    (r'ServerSignature\s+On',               'ServerSignature Off'),
    (r'ServerTokens\s+\w+',                 'ServerTokens Prod'),
    (r'Options\s+(Indexes\s+)',             'Options -Indexes '),
    (r'Options\s+Indexes$',                 'Options -Indexes'),
    (r'TraceEnable\s+On',                   'TraceEnable Off'),
    (r'LimitRequestBody\s+0\b',             'LimitRequestBody 10485760'),
    (r'SSLProtocol\s+.*',                   'SSLProtocol -all +TLSv1.2 +TLSv1.3'),
    (r'AllowOverride\s+All\b',              'AllowOverride None'),
    (r'Timeout\s+\d{4,}',                   'Timeout 60'),
]

_APACHE_HEADERS = [
    "",
    "# Security Headers added by Cybrain",
    'Header always set X-Frame-Options "DENY"',
    'Header always set X-Content-Type-Options "nosniff"',
    'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
    'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
    'Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"',
    "",
]
APACHE_SECURITY_HEADERS = "\n".join(_APACHE_HEADERS)


class CybrainAgent:
    """
    Cybrain AI Security Analysis Engine.
    Uses Gemini 2.0 Flash when available; pure Python offline fallback otherwise.
    """

    def __init__(self):
        self.chat_history    = []
        self.current_context = {}
        self.ai_active       = False
        self.model           = None
        self.openrouter_key  = _OPENROUTER_KEY

        if _GENAI_AVAILABLE:
            try:
                # Use 1.5-flash for better compatibility with older library versions like 0.5.4
                model_name = "gemini-1.5-flash"
                self.model     = genai.GenerativeModel(model_name)
                self.ai_active = True
                print(f"[ENGINE] Gemini {model_name} connected [OK]")
            except Exception as e:
                print("[ENGINE] Gemini unavailable: {} - offline mode active".format(e))
        else:
            print("[ENGINE] Offline mode (no GEMINI_API_KEY or google-generativeai)")

    def _gemini(self, prompt, system=""):
        """Call Gemini. Returns text or None on failure."""
        if not self.ai_active or not self.model:
            return None
        try:
            full_prompt = "{}\n\n{}".format(system, prompt) if system else prompt
            resp = self.model.generate_content(full_prompt)
            return resp.text
        except Exception as e:
            print("[ENGINE] Gemini call failed: {}".format(e))
            return None

    def _call_openrouter(self, prompt, system=""):
        """Call OpenRouter (Mistral/Llama). Returns text or None on failure."""
        if not self.openrouter_key:
            return None
        try:
            url = "https://openrouter.ai/api/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {self.openrouter_key}",
                "HTTP-Referer": "https://cybrain-ai.netlify.app",
                "X-Title": "Cybrain AI",
            }
            payload = {
                "model": "openrouter/free",
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt}
                ]
            }
            resp = requests.post(url, headers=headers, json=payload, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                return data['choices'][0]['message']['content']
            else:
                print(f"[ENGINE] OpenRouter error {resp.status_code}: {resp.text}")
                return None
        except requests.exceptions.Timeout:
            print("[ENGINE] OpenRouter request timed out (30s)")
            return None
        except Exception as e:
            print(f"[ENGINE] OpenRouter critical error: {e}")
            import traceback
            traceback.print_exc()
            return None

    # =========================================================================
    #  CHAT
    # =========================================================================

    def chat(self, user_message, context=None):
        """Security Q&A. Online: Gemini. Offline: rule-based."""
        self.current_context = context or {}

        if self.ai_active:
            system = (
                "You are Cybrain, a professional cybersecurity AI assistant. "
                "Answer questions about web security, network security, OWASP Top 10 2025, "
                "CVEs, secure coding practices, and vulnerability remediation. "
                "Be concise, technical, and always provide code examples. "
                "Format responses in Markdown."
            )
            ctx_str = ""
            if self.current_context:
                ctx_str = (
                    "\n\nCurrent scan context:\n"
                    "Target: {}\nRisk: {}\nTotal findings: {}"
                ).format(
                    self.current_context.get("target", "N/A"),
                    self.current_context.get("risk", "N/A"),
                    self.current_context.get("total", 0),
                )
            history_str = ""
            for turn in self.chat_history[-4:]:
                history_str += "User: {}\nAssistant: {}\n\n".format(
                    turn["q"], turn["a"]
                )
            full_prompt = "{}User: {}{}".format(history_str, user_message, ctx_str)
            result = self._gemini(full_prompt, system=system)
            if result:
                self.chat_history.append({"q": user_message, "a": result})
                return result

        reply = self._answer_offline(user_message.lower(), self.current_context)
        self.chat_history.append({"q": user_message, "a": reply})
        return reply

    def _answer_offline(self, msg, context):
        """Rule-based security Q&A - offline fallback."""
        if context and any(k in msg for k in [
            "finding", "explain", "result", "scan", "vulnerability", "found"
        ]):
            return self._explain_context(context)

        if any(k in msg for k in ["sql injection", "sqli"]):
            return (
                "## SQL Injection (CWE-89)\n\n"
                "**Attack:** Injecting SQL code into user inputs.\n\n"
                "**Fix:**\n```python\n"
                "cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))\n"
                "```\n\n**CVSS:** 9.8 CRITICAL | **OWASP:** A05:2025"
            )

        if any(k in msg for k in ["xss", "cross-site scripting"]):
            return (
                "## Cross-Site Scripting (CWE-79)\n\n"
                "**Attack:** Injecting JS that runs in victim browsers.\n\n"
                "**Fix:**\n```python\n"
                "from markupsafe import escape\n"
                "safe = escape(user_input)\n"
                "```\n\n**CVSS:** 7.4 HIGH | **OWASP:** A05:2025"
            )

        if "owasp" in msg:
            return (
                "## OWASP Top 10 - 2025\n\n"
                "| # | Category | Risk |\n"
                "|---|----------|------|\n"
                "| A01 | Broken Access Control | CRITICAL |\n"
                "| A02 | Security Misconfiguration | HIGH |\n"
                "| A03 | Software Supply Chain | HIGH |\n"
                "| A04 | Cryptographic Failures | HIGH |\n"
                "| A05 | Injection (SQLi/XSS/SSTI) | CRITICAL |\n"
                "| A06 | Insecure Design | HIGH |\n"
                "| A07 | Authentication Failures | CRITICAL |\n"
                "| A08 | Integrity Failures | HIGH |\n"
                "| A09 | Logging Failures | MEDIUM |\n"
                "| A10 | Exception Mishandling | MEDIUM |"
            )

        if any(k in msg for k in ["header", "csp", "hsts", "x-frame"]):
            return (
                "## HTTP Security Headers\n\n"
                "```apache\n"
                "Header always set Content-Security-Policy \"default-src 'self'\"\n"
                "Header always set X-Frame-Options \"DENY\"\n"
                "Header always set X-Content-Type-Options \"nosniff\"\n"
                "Header always set Strict-Transport-Security \"max-age=31536000\"\n"
                "```"
            )

        if any(k in msg for k in ["apache", "httpd", "htaccess"]):
            return (
                "## Apache Hardening Checklist\n\n"
                "```apache\n"
                "ServerTokens Prod\n"
                "ServerSignature Off\n"
                "Options -Indexes\n"
                "TraceEnable Off\n"
                "SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
                "```"
            )

        if any(k in msg for k in ["severity", "critical", "risk level"]):
            return (
                "## Severity Levels\n\n"
                "| Level | CVSS | Action |\n"
                "|-------|------|--------|\n"
                "| CRITICAL | 9.0-10.0 | Fix immediately |\n"
                "| HIGH | 7.0-8.9 | Fix within 48 hours |\n"
                "| MEDIUM | 4.0-6.9 | Fix within 2 weeks |\n"
                "| LOW | 0.1-3.9 | Fix when possible |"
            )

        return (
            "## Cybrain Security Engine - Offline Mode\n\n"
            "Ask me about:\n"
            "* SQL Injection, XSS, SSTI, SSRF, Command Injection\n"
            "* OWASP Top 10 2025\n"
            "* HTTP Security Headers\n"
            "* Apache Hardening\n"
            "* Severity levels and CVSS\n"
            "* Your scan findings - 'explain my findings'"
        )

    def _explain_context(self, context):
        total  = context.get("total", 0)
        risk   = context.get("risk", "UNKNOWN")
        target = context.get("target", "target")

        if total == 0:
            return (
                "## Scan Results - {}\n\n"
                "No vulnerabilities found. Verify:\n"
                "* The target was reachable and fully scanned\n"
                "* Try a known-vulnerable target: testphp.vulnweb.com"
            ).format(target)

        advice = {
            "CRITICAL": "[!] IMMEDIATE ACTION REQUIRED. Critical vulns are exploitable NOW.",
            "HIGH":     "[!] Fix within 24-48 hours. Serious security risk.",
            "MEDIUM":   "[~] Fix within 2 weeks. Address in next release.",
            "LOW":      "[i] Fix when convenient. Minor improvements.",
        }.get(risk, "Review findings below.")

        return (
            "## Security Assessment - {}\n\n"
            "**Findings:** {} | **Risk:** {}\n\n"
            "{}\n\n"
            "**Next steps:**\n"
            "1. Review CRITICAL and HIGH findings first\n"
            "2. Follow the remediation steps in each finding\n"
            "3. Re-scan after fixes to verify\n"
            "4. Export the report for documentation"
        ).format(target, total, risk, advice)

    # =========================================================================
    #  FINDINGS ANALYSIS
    # =========================================================================

    def analyze_findings(self, findings, target, scan_type="web"):
        """Generate executive report from scan findings."""
        if not findings:
            return "## No Findings\n\nScan completed with zero vulnerabilities detected."

        if self.ai_active:
            system = (
                "You are Cybrain, a professional penetration tester writing an "
                "executive security report. Be precise, technical, and concise. "
                "Format as professional Markdown. Include: executive summary, "
                "top 5 prioritized fixes with code examples, "
                "compliance impact (GDPR/PCI-DSS/ISO 27001), security score."
            )
            prompt = (
                "Target: {}\nScan type: {}\n\n"
                "Findings ({} total):\n{}\n\n"
                "Write a professional security assessment report."
            ).format(target, scan_type, len(findings),
                     json.dumps(findings[:20], indent=2))
            result = self._gemini(prompt, system=system)
            if result:
                return result

        return self._gemini(prompt, system=system) or self._analyze_offline(findings, target, scan_type)

    def _analyze_offline(self, findings, target, scan_type):
        counts = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1

        total_w = sum(
            SEVERITY_WEIGHT.get(f.get("severity", "INFO"), 0) for f in findings
        )
        score = max(0, 100 - min(total_w * 3, 95))
        risk  = next(
            (s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts.get(s, 0) > 0),
            "INFO",
        )
        now = datetime.now().strftime("%Y-%m-%d %H:%M")

        seen  = set()
        fixes = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            for f in findings:
                if f.get("severity") != sev:
                    continue
                code = f.get("code", f.get("title", ""))
                if code in seen:
                    continue
                seen.add(code)
                cmd = next(
                    (d["fix_cmd"] for k, d in CVE_DATABASE.items()
                     if k.lower() in code.lower()),
                    "Review finding details.",
                )
                fixes.append(
                    "**{}. [{}] {}**\n```\n{}\n```".format(
                        len(fixes) + 1, sev, code, cmd
                    )
                )
                if len(fixes) >= 5:
                    break
            if len(fixes) >= 5:
                break

        has_crit = counts.get("CRITICAL", 0) > 0
        has_high = counts.get("HIGH", 0) > 0
        gdpr = "[!] VIOLATION RISK" if has_crit else "[~] Monitor"
        pci  = "[!] FAIL"           if has_crit or has_high else "[~] Review"
        iso  = "[!] NON-CONFORMITY" if has_high else "[~] Minor gaps"

        score_text = (
            "Excellent." if score >= 90 else
            "Good baseline - fix HIGH findings." if score >= 70 else
            "Significant gaps - immediate action needed." if score >= 50 else
            "Critical posture - system may be compromised."
        )

        parts = [
            "# Security Report - {}".format(target),
            "",
            "**Date:** {} | **Scan:** {} | **Risk:** {}".format(
                now, scan_type.upper(), risk
            ),
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            "Assessment identified **{}** finding(s): "
            "{} Critical, {} High, {} Medium, {} Low.".format(
                len(findings),
                counts.get("CRITICAL", 0), counts.get("HIGH", 0),
                counts.get("MEDIUM", 0),   counts.get("LOW", 0),
            ),
            "",
            "## 2. Top Priority Fixes",
            "",
        ]
        parts += fixes
        parts += [
            "",
            "## 3. Compliance Impact",
            "",
            "| Standard | Status |",
            "|----------|--------|",
            "| GDPR | {} |".format(gdpr),
            "| PCI-DSS | {} |".format(pci),
            "| ISO 27001 | {} |".format(iso),
            "",
            "## 4. Security Score",
            "",
            "**{}/100** - {}".format(score, score_text),
        ]
        return "\n".join(parts)

    # =========================================================================
    #  CODE ANALYSIS
    # =========================================================================

    def analyze_code_file(self, content, filename, language="Unknown"):
        """Deep AI analysis of a code file."""
        if self.ai_active:
            system = (
                "You are a senior application security engineer performing a "
                "code security review. Identify all security vulnerabilities "
                "with CWE references, line numbers, and concrete fix examples. "
                "Format as Markdown. Be concise but thorough."
            )
            truncated = content[:8000] + (
                "\n...[truncated]" if len(content) > 8000 else ""
            )
            prompt = (
                "Language: {}\nFile: {}\n\n"
                "```{}\n{}\n```\n\n"
                "Perform a complete security review. List all vulnerabilities "
                "with severity (CRITICAL/HIGH/MEDIUM/LOW), CWE, and fix."
            ).format(language, filename, language.lower(), truncated)
            result = self._gemini(prompt, system=system)
            if result:
                return result

        return None

    # =========================================================================
    #  CODE FIXER
    # =========================================================================

    def fix_code(self, content, filename, language=None):
        """Apply automatic code fixes (regex templates + optional AI)."""
        ext          = filename.rsplit(".", 1)[-1].lower()
        lang         = language or ext
        fixed        = content
        changes_made = []

        for vuln_name, rules in CODE_FIX_TEMPLATES.items():
            patterns = rules.get(lang) or rules.get("py", [])
            for old_pat, new_val in patterns:
                if re.search(old_pat, fixed, re.IGNORECASE):
                    replacement = "# CYBRAIN FIX: {}\n{}".format(vuln_name, new_val)
                    fixed = re.sub(
                        old_pat, replacement, fixed, flags=re.IGNORECASE
                    )
                    changes_made.append("[+] Fixed: {}".format(vuln_name))

        if "subprocess.run" in fixed and "import subprocess" not in fixed:
            fixed = "import subprocess\n" + fixed
            changes_made.append("[+] Added: import subprocess")
        if "os.environ" in fixed and "import os" not in fixed:
            fixed = "import os\n" + fixed
            changes_made.append("[+] Added: import os")

        if not changes_made:
            changes_made = ["No automatic fixes applied - review manually."]

        if self.ai_active:
            system = (
                "You are a security code fixer. Fix ALL security vulnerabilities "
                "in the provided code. Add comments explaining each fix. "
                "Return ONLY the fixed code, no explanation outside the code."
            )
            prompt = (
                f"Fix all security vulnerabilities in the following code. "
                f"Identify and fix findings like SQLi, XSS, Command Injection, etc. "
                "Return ONLY the fixed code inside a markdown block.\n\n"
                f"```{lang}\n{content[:10000]}\n```"
            )
            ai_fixed = self._gemini(prompt, system=system)
            if ai_fixed:
                m = re.search(r"```(?:\w+)?\n(.*?)```", ai_fixed, re.DOTALL)
                if m:
                    fixed = m.group(1)
                    changes_made.append("[+] AI deep fix applied")

        explanation = "\n".join([
            f"## Code Fix Report - {filename}",
            "",
            f"**Engine:** Cybrain v2.0 ({'AI + ' if self.ai_active else ''}Static Fixer)",
            f"**Changes:** {len(changes_made)}",
            "",
            "## Changes Made",
            "",
        ] + changes_made + [
            "",
            "## Note",
            "",
            "Review all changes before deploying. Run your test suite.",
        ])

        return {
            "explanation": explanation,
            "fixed_code":  fixed,
            "filename":    filename,
            "language":    lang,
        }

    # =========================================================================
    #  APACHE CONFIG FIXER
    # =========================================================================

    def fix_apache_config(self, config_content, findings=None):
        """Apply Apache hardening fixes."""
        fixed   = config_content
        changes = []

        for old_pat, new_val in APACHE_FIXES:
            if re.search(old_pat, fixed, re.MULTILINE | re.IGNORECASE):
                fixed = re.sub(
                    old_pat, new_val, fixed,
                    flags=re.MULTILINE | re.IGNORECASE,
                )
                changes.append("[+] {} -> {}".format(old_pat, new_val[:50]))

        if ("Content-Security-Policy" not in fixed and
                "X-Frame-Options" not in fixed):
            if "</VirtualHost>" in fixed:
                fixed = fixed.replace(
                    "</VirtualHost>",
                    APACHE_SECURITY_HEADERS + "\n</VirtualHost>",
                )
            else:
                fixed += "\n" + APACHE_SECURITY_HEADERS
            changes.append("[+] Added all security headers")

        if re.search(r"<Directory[^>]+>.*?ProxyPass",
                      fixed, re.DOTALL | re.IGNORECASE):
            changes.append(
                "[!] Manual fix needed: Move ProxyPass outside <Directory>"
            )

        if self.openrouter_key:
            system = (
                "You are an Apache Security Hardening expert. Fix ALL security vulnerabilities "
                "in the provided configuration. Apply industry best practices (CIS benchmarks). "
                "Return ONLY the fixed configuration, no explanation outside the code."
            )
            prompt = (
                "Fix all security vulnerabilities in this Apache config:\n\n"
                f"```apache\n{fixed[:6000]}\n```"
            )
            ai_fixed = self._call_openrouter(prompt, system=system)
            if ai_fixed:
                m = re.search(r"```(?:apache)?\n(.*?)```", ai_fixed, re.DOTALL | re.IGNORECASE)
                if m:
                    fixed = m.group(1)
                    changes.append("[+] OpenRouter deep hardening applied")
                else:
                    # If not in code block, try to clean it
                    fixed = ai_fixed.strip()
                    changes.append("[+] OpenRouter deep hardening applied (raw)")

        if not changes:
            changes = ["Config looks clean - no automatic fixes applied."]

        explanation = "\n".join([
            "## Apache Config Fix Report",
            "",
            "**Engine:** Cybrain v2.0",
            f"**Fixes applied: {len(changes)}**",
            "",
            "## Changes",
            "",
        ] + changes + [
            "",
            "## Verify",
            "",
            "```bash",
            "apachectl configtest",
            "```",
        ])

        return {"explanation": explanation, "fixed_config": fixed}

    def analyze_network_findings(self, findings, recon_data, target):
        """Alias for network scan findings analysis."""
        return self.analyze_findings(findings, target, "network")

    def reset_chat(self):
        """Clear conversation history."""
        self.chat_history    = []
        self.current_context = {}