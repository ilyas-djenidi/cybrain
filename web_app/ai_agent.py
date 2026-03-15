"""
CYBRAIN — AI Security Agent
Powered by Google Gemini 1.5 Flash (Free tier)
PFE Master 2 — Information Security
"""

import os
import re
import json
from dotenv import load_dotenv

load_dotenv()

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

SYSTEM_PROMPT = """You are Cybrain AI — an expert 
cybersecurity analyst and penetration tester with 
15 years of experience in web security, network 
security, and secure code review.

Your capabilities:
1. Analyze vulnerability scan findings deeply
2. Explain security issues in clear language
3. Provide concrete step-by-step fixes
4. Analyze code files for security flaws
5. Fix vulnerable code and configurations
6. Analyze network scan findings

Always:
- Reference CVE/CWE numbers when relevant
- Give copy-paste ready fix examples
- Prioritize by severity: CRITICAL > HIGH > MEDIUM > LOW
- Be specific about line numbers and exact issues
- Explain real-world attack impact clearly

When fixing code/configs:
- Return the COMPLETE fixed version
- Add security comments explaining each fix
- Never break existing functionality
- Follow OWASP and CIS Benchmark guidelines"""


class CybrainAgent:

    def __init__(self):
        self.model = None
        self.chat_session = None
        self.current_context = {}
        self._init_gemini()

    def _init_gemini(self):
        """Initialize Gemini model."""
        if not GEMINI_AVAILABLE:
            print(
                "[AI] google-generativeai not installed. "
                "Run: pip install google-generativeai"
            )
            return
        if not GEMINI_API_KEY:
            print(
                "[AI] No GEMINI_API_KEY in environment"
            )
            return
        try:
            genai.configure(api_key=GEMINI_API_KEY)
            self.model = genai.GenerativeModel(
                model_name="gemini-1.5-flash",
                system_instruction=SYSTEM_PROMPT,
                generation_config={
                    "temperature":     0.3,
                    "max_output_tokens": 8192,
                    "top_p":           0.95,
                }
            )
            print("[AI] Gemini 1.5 Flash initialized [OK]")
        except Exception as e:
            print(f"[AI] Gemini init error: {e}")
            self.model = None

    def _call(self, prompt, use_chat=False):
        """Call Gemini API with fallback."""
        if not self.model:
            return self._offline_response()
        try:
            if use_chat and self.chat_session:
                response = self.chat_session.send_message(
                    prompt
                )
            else:
                response = self.model.generate_content(
                    prompt
                )
            return response.text
        except Exception as e:
            error_str = str(e)
            if "quota" in error_str.lower():
                return (
                    "⚠️ Gemini API quota reached. "
                    "Please wait a moment and try again. "
                    "Free tier: 15 requests/minute."
                )
            return f"AI error: {error_str}"

    def _offline_response(self):
        return (
            "⚠️ AI Agent offline.\n\n"
            "Check that GEMINI_API_KEY is set in "
            "your .env file and "
            "google-generativeai is installed:\n"
            "pip install google-generativeai"
        )

    def start_chat(self):
        """Start a new Gemini chat session."""
        if self.model:
            self.chat_session = self.model.start_chat(
                history=[]
            )

    def reset_chat(self):
        """Reset chat history."""
        self.chat_session = None
        self.current_context = {}

    # ── CHATBOT ─────────────────────────────────────────────
    def chat(self, user_message, context=None):
        """Security chatbot with conversation memory."""
        if not self.chat_session:
            self.start_chat()

        # Inject context on first message
        if context and context != self.current_context:
            self.current_context = context
            ctx = (
                f"[SCAN CONTEXT]\n"
                f"Target: {context.get('target','')}\n"
                f"Total findings: "
                f"{context.get('total', 0)}\n"
                f"Overall risk: "
                f"{context.get('risk','')}\n"
                f"Scan type: "
                f"{context.get('scan_type','web')}\n"
                f"[USER MESSAGE]\n{user_message}"
            )
            return self._call(ctx, use_chat=True)

        return self._call(user_message, use_chat=True)

    # ── FINDINGS ANALYSIS ────────────────────────────────────
    def analyze_findings(self, findings, target,
                         scan_type="web"):
        """Deep AI analysis of scan findings."""
        if not findings:
            return "No findings to analyze."

        findings_text = ""
        for i, f in enumerate(findings[:20], 1):
            sev  = f.get("severity", "INFO")
            code = f.get("code", f.get("title", ""))
            msg  = re.sub(
                r'<[^>]+>', '',
                f.get("message",
                      f.get("description", ""))
            )[:300]
            findings_text += (
                f"\n{i}. [{sev}] {code}\n"
                f"   {msg}\n"
            )

        prompt = f"""
Cybersecurity assessment for: {target}
Scan type: {scan_type}
Total findings: {len(findings)}

{findings_text}

Provide a professional security report with:

## 1. EXECUTIVE SUMMARY
2-3 sentences suitable for a non-technical manager.

## 2. CRITICAL RISK ANALYSIS
What can be actively exploited right now?
What is the immediate business impact?

## 3. ATTACK CHAIN SCENARIO
How would a real attacker chain these vulnerabilities?
Step by step attack narrative.

## 4. TOP 5 PRIORITY FIXES
Most impactful fixes ordered by priority.
Include specific commands/code examples.

## 5. COMPLIANCE IMPACT
Impact on: GDPR, PCI-DSS, ISO 27001, HIPAA

## 6. SECURITY SCORE
Rate overall security: X/100
Justify the score.
"""
        return self._call(prompt)

    # ── CODE ANALYSIS ────────────────────────────────────────
    def analyze_code_file(self, content, filename,
                          language=None):
        """Deep vulnerability analysis of code file."""
        lang = language or self._detect_lang(filename)
        prompt = f"""
Perform a comprehensive security code review.
File: {filename}
Language: {lang}
```{lang.lower() if lang else ''}
{content[:8000]}
```

Provide a detailed security audit:

## VULNERABILITY FINDINGS
For each issue found:
| # | Line | Severity | Type | CWE | Description |
List all vulnerabilities in this table format.

## DETAILED ANALYSIS
For each CRITICAL and HIGH finding:
- Exact location (line number)
- How an attacker exploits it
- Proof of concept attack
- CVSS score

## SECURITY SCORE
Rate this code: X/100

## QUICK WINS
Issues fixable in under 5 minutes each.

## SHOULD I FIX IT?
Clearly state: "Yes, I can generate a complete 
fixed version of this file."
"""
        result = self._call(prompt)
        self.current_context = {
            "type":     "code",
            "filename": filename,
            "language": lang,
            "content":  content,
        }
        # Start fresh chat with code context
        if self.model:
            self.chat_session = self.model.start_chat(
                history=[
                    {
                        "role": "user",
                        "parts": [prompt]
                    },
                    {
                        "role": "model",
                        "parts": [result]
                    },
                ]
            )
        return result

    def _detect_lang(self, filename):
        ext = filename.split(".")[-1].lower()
        return {
            "py": "Python", "php": "PHP",
            "js": "JavaScript", "ts": "TypeScript",
            "java": "Java", "cs": "C#",
            "rb": "Ruby", "go": "Go",
            "cpp": "C++", "c": "C",
            "sql": "SQL", "jsx": "JavaScript",
            "tsx": "TypeScript",
            "conf": "Apache Config",
            "htaccess": "Apache Config",
        }.get(ext, "Unknown")

    # ── CODE FIX ─────────────────────────────────────────────
    def fix_code(self, content, filename,
                 language=None):
        """Generate complete secured version of code."""
        lang = language or self._detect_lang(filename)
        prompt = f"""
Generate the COMPLETE FIXED and SECURED version of 
this {lang} file.

Original file: {filename}
```{lang.lower() if lang else ''}
{content[:8000]}
```

Requirements:
1. Fix ALL security vulnerabilities
2. Add security comment for EVERY fix
3. Do NOT change functionality
4. Follow OWASP Secure Coding Guidelines
5. Use parameterized queries for all SQL
6. Sanitize/validate all user inputs
7. Use strong cryptography (bcrypt, SHA-256)
8. Add proper error handling

FORMAT YOUR RESPONSE EXACTLY LIKE THIS:

## CHANGES MADE
List every security fix with line references.

## FIXED CODE
```{lang.lower() if lang else 'text'}
[COMPLETE FIXED FILE HERE - no truncation]
```

## SECURITY IMPROVEMENTS SUMMARY
Brief summary of all security improvements.
"""
        if self.chat_session:
            result = self._call(prompt, use_chat=True)
        else:
            result = self._call(prompt)

        # Extract fixed code block
        pattern = (
            rf'```{re.escape(lang.lower() if lang else "")}'
            r'?\n(.*?)\n```'
        )
        match = re.search(pattern, result, re.DOTALL)
        if not match:
            match = re.search(
                r'```\w*\n(.*?)\n```',
                result, re.DOTALL
            )

        return {
            "explanation": result,
            "fixed_code":  match.group(1) if match else None,
            "filename":    filename,
            "language":    lang,
        }

    # ── APACHE CONFIG FIX ────────────────────────────────────
    def fix_apache_config(self, config_content,
                          findings):
        """Fix Apache misconfiguration automatically."""
        issues = "\n".join([
            f"- [{f.get('severity','')}] "
            f"{f.get('code','')}: "
            f"{re.sub(r'<[^>]+>','',f.get('message',''))[:150]}"
            for f in findings[:20]
        ])

        prompt = f"""
Fix this Apache configuration. These issues were found:

{issues}

Original config:
```apache
{config_content[:6000]}
```

Generate the COMPLETE FIXED Apache configuration.

Apply ALL these fixes:
1. Replace all Order/Allow/Deny with Require directives
2. Disable directory listing: Options -Indexes
3. Add security headers:
   Header always set Content-Security-Policy "default-src 'self'"
   Header always set X-Frame-Options "DENY"
   Header always set X-Content-Type-Options "nosniff"
   Header always set Strict-Transport-Security "max-age=31536000"
   Header always set Referrer-Policy "strict-origin-when-cross-origin"
4. Fix SSL: SSLProtocol -all +TLSv1.2 +TLSv1.3
5. Strong ciphers: SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
6. Add: ServerTokens Prod + ServerSignature Off
7. Add: TraceEnable Off
8. Fix: LimitRequestBody 10485760
9. Fix: Timeout 300
10. Move ProxyPass outside Directory blocks
11. Fix all syntax errors
12. Add SymLinksIfOwnerMatch

FORMAT EXACTLY:

## CHANGES MADE
List every fix with line references.

## FIXED CONFIGURATION
```apache
[COMPLETE FIXED CONFIG HERE]
```
"""
        result = self._call(prompt)
        match = re.search(
            r'```apache\n(.*?)\n```',
            result, re.DOTALL
        )
        if not match:
            match = re.search(
                r'```\w*\n(.*?)\n```',
                result, re.DOTALL
            )

        return {
            "explanation":  result,
            "fixed_config": match.group(1)
                            if match else None,
        }

    # ── NETWORK ANALYSIS ─────────────────────────────────────
    def analyze_network_findings(self, findings,
                                  recon_data, target):
        """Specialized network vulnerability analysis."""
        open_ports = recon_data.get(
            "ports", {}
        ).get("open", [])
        os_info = recon_data.get("os", {})

        ports_str = ", ".join([
            f"{p['port']}/{p['service']}"
            for p in open_ports[:15]
        ])
        findings_text = "\n".join([
            f"- [{f.get('severity','')}] "
            f"{f.get('code', f.get('title',''))}"
            for f in findings[:15]
        ])

        prompt = f"""
Network security assessment:
Target: {target}
OS detected: {os_info.get('os', 'Unknown')}
Open ports: {ports_str}

Vulnerabilities:
{findings_text}

Provide:

## 1. ATTACK SURFACE ANALYSIS
How exposed is this host to attacks?

## 2. EXPLOITABLE NOW
What can be attacked without any authentication?

## 3. STEP-BY-STEP ATTACK SCENARIO
How would an attacker compromise this host?

## 4. HARDENING COMMANDS
Exact commands to fix each issue:
- iptables/ufw rules
- Service configuration changes
- Package updates needed

## 5. MONITORING SETUP
What to log and alert on for this host.
"""
        return self._call(prompt)
