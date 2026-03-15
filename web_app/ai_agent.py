"""
CYBRAIN — AI Security Agent
Powered by Google Gemini 2.0 Flash
PFE Master 2 — Information Security
"""

import os
import re
import time
import json
from dotenv import load_dotenv

load_dotenv()

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

# ── Rate limiting tracker ────────────────────────────────
_request_times = []
MAX_RPM = 12  # Stay under 15 RPM limit with buffer

def _check_rate_limit():
    """
    Enforce rate limiting to avoid quota errors.
    Returns True if OK to proceed, False if limited.
    """
    global _request_times
    now = time.time()

    # Remove requests older than 60 seconds
    _request_times = [
        t for t in _request_times
        if now - t < 60
    ]

    if len(_request_times) >= MAX_RPM:
        # Calculate wait time
        oldest = _request_times[0]
        wait   = 60 - (now - oldest)
        return False, max(0, wait)

    _request_times.append(now)
    return True, 0

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
        self.model        = None
        self.chat_session = None
        self.current_context = {}
        self._init_gemini()

    def _init_gemini(self):
        if not GEMINI_AVAILABLE:
            print(
                "[AI] google-generativeai not installed.\n"
                "Run: pip install google-generativeai"
            )
            return
        if not GEMINI_API_KEY:
            print("[AI] No GEMINI_API_KEY in .env")
            return
        try:
            genai.configure(api_key=GEMINI_API_KEY)
            self.model = genai.GenerativeModel(
                model_name="gemini-2.0-flash",
                system_instruction=SYSTEM_PROMPT,
                generation_config={
                    "temperature":       0.3,
                    "max_output_tokens": 8192,
                    "top_p":             0.95,
                }
            )
            print("[AI] Gemini 2.0 Flash ready [OK]")
        except Exception as e:
            print(f"[AI] Init error: {e}")
            self.model = None

    def _call(self, prompt, use_chat=False,
              retries=2):
        """
        Call Gemini with rate limiting + retry logic.
        """
        if not self.model:
            return self._offline_response()

        # Check rate limit BEFORE calling
        ok, wait_secs = _check_rate_limit()
        if not ok:
            wait_rounded = round(wait_secs) + 1
            return (
                f"[Rate limit reached] "
                f"({MAX_RPM} req/min free tier).\n\n"
                f"Please wait **{wait_rounded} seconds** "
                f"and try again.\n\n"
                f"Tip: The free tier allows "
                f"15 requests/minute. "
                f"Space out your requests slightly."
            )

        for attempt in range(retries + 1):
            try:
                if use_chat and self.chat_session:
                    resp = self.chat_session.send_message(
                        prompt
                    )
                else:
                    resp = self.model.generate_content(
                        prompt
                    )
                return resp.text

            except Exception as e:
                err = str(e).lower()

                # Quota / rate limit error
                if any(k in err for k in [
                    "quota", "rate", "429",
                    "resource_exhausted",
                    "too many requests"
                ]):
                    if attempt < retries:
                        wait = 30 * (attempt + 1)
                        print(
                            f"[AI] Rate limited. "
                            f"Waiting {wait}s... "
                            f"(attempt {attempt+1})"
                        )
                        time.sleep(wait)
                        continue
                    return (
                        "**Gemini API quota reached.**\n\n"
                        "The free tier allows **15 requests "
                        "per minute** and **1,500 per day**."
                        "\n\n"
                        "**Options:**\n"
                        "• Wait 60 seconds and try again\n"
                        "• The scan results above are "
                        "complete — AI analysis is optional\n"
                        "• Upgrade at: "
                        "https://aistudio.google.com"
                    )

                # Model not found error
                if any(k in err for k in [
                    "not found", "404", "not supported"
                ]):
                    # Try fallback model
                    if attempt == 0:
                        print(
                            "[AI] Model error, "
                            "trying gemini-1.5-flash-latest"
                        )
                        try:
                            genai.configure(
                                api_key=GEMINI_API_KEY
                            )
                            self.model = (
                                genai.GenerativeModel(
                                    "gemini-1.5-flash-latest"
                                )
                            )
                            resp = self.model.generate_content(
                                prompt
                            )
                            return resp.text
                        except Exception:
                            pass
                    return (
                        "AI model unavailable.\n\n"
                        "Try updating the library:\n"
                        "`pip install -U google-generativeai`"
                    )

                # Generic error
                print(f"[AI] Error attempt {attempt}: {e}")
                if attempt < retries:
                    time.sleep(5)
                    continue
                return (
                    f"AI temporarily unavailable.\n\n"
                    f"Error: {str(e)[:100]}\n\n"
                    "The security scan results above "
                    "are complete and accurate. "
                    "AI analysis is an optional enhancement."
                )

        return "AI request failed after retries."

    def _offline_response(self):
        return (
            "**AI Agent offline.**\n\n"
            "Check:\n"
            "• GEMINI_API_KEY set in .env file\n"
            "• `pip install google-generativeai`\n\n"
            "Note: Scan results work without AI — "
            "AI only enhances analysis."
        )

    def start_chat(self):
        if self.model:
            self.chat_session = (
                self.model.start_chat(history=[])
            )

    def reset_chat(self):
        self.chat_session    = None
        self.current_context = {}

    def chat(self, user_message, context=None):
        if not self.chat_session:
            self.start_chat()

        if context and context != self.current_context:
            self.current_context = context
            msg = (
                f"[SCAN CONTEXT]\n"
                f"Target: {context.get('target','')}\n"
                f"Total findings: "
                f"{context.get('total', 0)}\n"
                f"Risk: {context.get('risk','')}\n"
                f"[QUESTION]\n{user_message}"
            )
            return self._call(msg, use_chat=True)

        return self._call(user_message, use_chat=True)

    def analyze_findings(self, findings, target,
                         scan_type="web"):
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
                f"\n{i}. [{sev}] {code}\n   {msg}\n"
            )

        prompt = f"""
Security assessment: {target} ({scan_type})
Total: {len(findings)} findings

{findings_text}

## 1. EXECUTIVE SUMMARY (2-3 sentences)
## 2. CRITICAL RISK — what can be exploited NOW
## 3. ATTACK CHAIN — step by step scenario
## 4. TOP 5 PRIORITY FIXES with commands
## 5. COMPLIANCE IMPACT (GDPR/PCI-DSS/ISO27001)
## 6. SECURITY SCORE X/100 with justification
"""
        return self._call(prompt)

    def analyze_code_file(self, content, filename,
                          language=None):
        lang   = language or self._detect_lang(filename)
        prompt = f"""
Security code review for {filename} ({lang}):
```{lang.lower() if lang else ''}
{content[:6000]}
```

## VULNERABILITY TABLE
| # | Line | Severity | Type | CWE | Description |

## CRITICAL/HIGH DETAILS
Line, exploit method, PoC, CVSS score.

## SECURITY SCORE X/100

## QUICK WINS (fixable < 5 min)

## Can you fix this? State clearly yes/no.
"""
        result = self._call(prompt)
        self.current_context = {
            "type": "code", "filename": filename,
            "language": lang, "content": content,
        }
        if self.model:
            try:
                self.chat_session = (
                    self.model.start_chat(history=[
                        {"role": "user",
                         "parts": [prompt]},
                        {"role": "model",
                         "parts": [result]},
                    ])
                )
            except Exception:
                pass
        return result

    def _detect_lang(self, filename):
        ext = filename.split(".")[-1].lower()
        return {
            "py": "Python",   "php": "PHP",
            "js": "JavaScript","ts": "TypeScript",
            "java": "Java",   "cs": "C#",
            "rb": "Ruby",     "go": "Go",
            "cpp": "C++",     "c": "C",
            "sql": "SQL",     "jsx": "JavaScript",
            "tsx": "TypeScript",
            "conf": "Apache Config",
            "htaccess": "Apache Config",
        }.get(ext, "Unknown")

    def fix_code(self, content, filename,
                 language=None):
        lang   = language or self._detect_lang(filename)
        prompt = f"""
Generate COMPLETE FIXED version of {filename} ({lang}).
```{lang.lower() if lang else ''}
{content[:6000]}
```

Fix ALL vulnerabilities. Keep functionality.
Use OWASP guidelines. Add security comments.

## CHANGES MADE
## FIXED CODE
```{lang.lower() if lang else 'text'}
[complete fixed file]
```
## SUMMARY
"""
        result = (
            self._call(prompt, use_chat=True)
            if self.chat_session
            else self._call(prompt)
        )

        for pat in [
            rf'```{re.escape(lang.lower() if lang else "")}?\n(.*?)\n```',
            r'```\w*\n(.*?)\n```',
        ]:
            m = re.search(pat, result, re.DOTALL)
            if m:
                return {
                    "explanation": result,
                    "fixed_code":  m.group(1),
                    "filename":    filename,
                    "language":    lang,
                }

        return {
            "explanation": result,
            "fixed_code":  None,
            "filename":    filename,
            "language":    lang,
        }

    def fix_apache_config(self, config_content,
                          findings):
        issues = "\n".join([
            f"- [{f.get('severity','')}] "
            f"{f.get('code','')}: "
            f"{re.sub(chr(60)+r'[^>]+>','',f.get('message',''))[:120]}"
            for f in findings[:20]
        ])
        prompt = f"""
Fix this Apache config. Issues found:
{issues}
```apache
{config_content[:5000]}
```

Apply ALL standard security fixes.

## CHANGES MADE
## FIXED CONFIGURATION
```apache
[complete fixed config]
```
"""
        result = self._call(prompt)
        for pat in [
            r'```apache\n(.*?)\n```',
            r'```\w*\n(.*?)\n```',
        ]:
            m = re.search(pat, result, re.DOTALL)
            if m:
                return {
                    "explanation":  result,
                    "fixed_config": m.group(1),
                }

        return {
            "explanation":  result,
            "fixed_config": None,
        }

    def analyze_network_findings(self, findings,
                                  recon_data, target):
        ports_str = ", ".join([
            f"{p['port']}/{p['service']}"
            for p in recon_data.get(
                "ports", {}
            ).get("open", [])[:15]
        ])
        findings_text = "\n".join([
            f"- [{f.get('severity','')}] "
            f"{f.get('code', f.get('title',''))}"
            for f in findings[:15]
        ])
        prompt = f"""
Network assessment: {target}
OS: {recon_data.get('os',{}).get('os','Unknown')}
Open ports: {ports_str}
Findings: {findings_text}

## 1. ATTACK SURFACE
## 2. EXPLOITABLE NOW (no auth needed)
## 3. STEP-BY-STEP ATTACK SCENARIO
## 4. HARDENING COMMANDS (iptables/config)
## 5. MONITORING RECOMMENDATIONS
"""
        return self._call(prompt)
