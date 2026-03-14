"""
CYBRAIN — AI Security Agent
Uses OpenRouter FREE models (Llama 3.3 70B)
Analyzes vulnerabilities and generates fixes
"""

import requests
import json
import re
import os

OPENROUTER_API_URL = (
    "https://openrouter.ai/api/v1/chat/completions"
)

# Best free model with most tokens
FREE_MODEL = "meta-llama/llama-3.3-70b-instruct:free"
FALLBACK_MODEL = "deepseek/deepseek-r1:free"

SYSTEM_PROMPT = """You are Cybrain AI — an expert cybersecurity
analyst and penetration tester with 15 years of experience.

Your capabilities:
1. Analyze code files for vulnerabilities (SQLi, XSS, RCE, etc.)
2. Analyze Apache configurations for misconfigurations
3. Explain network vulnerabilities clearly
4. Generate detailed fix recommendations
5. Actually FIX the vulnerable code/config when asked
6. Answer security questions in the context of findings

When analyzing findings:
- Be specific about line numbers and exact issues
- Explain the real-world impact
- Provide concrete, copy-paste ready fixes
- Reference CVEs and CWE numbers
- Prioritize by severity: CRITICAL → HIGH → MEDIUM → LOW

When fixing code/configs:
- Return the COMPLETE fixed file
- Add security comments explaining each fix
- Never break existing functionality
- Follow security best practices (OWASP, CIS Benchmarks)

Response format for fixes:
Always wrap fixed code in: ```fixed\n...\n```
Always wrap explanations in clear sections.

You are integrated into the Cybrain security platform
for Master's thesis research (PFE) in Information Security."""


class CybrainAgent:

    def __init__(self, api_key=None):
        self.api_key = (
            api_key or
            os.environ.get("OPENROUTER_API_KEY", "")
        )
        self.conversation_history = []
        self.current_context = {}

    def _call_api(self, messages, model=FREE_MODEL,
                  max_tokens=4096):
        """Call OpenRouter API."""
        if not self.api_key:
            return self._offline_response(messages)

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type":  "application/json",
            "HTTP-Referer":  "https://cybrain.security",
            "X-Title":       "Cybrain Security Platform",
        }
        payload = {
            "model":       model,
            "messages":    messages,
            "max_tokens":  max_tokens,
            "temperature": 0.3,
        }
        try:
            resp = requests.post(
                OPENROUTER_API_URL,
                headers=headers,
                json=payload,
                timeout=60
            )
            data = resp.json()
            if "choices" in data:
                return data["choices"][0]["message"][
                    "content"
                ]
            elif "error" in data:
                # Try fallback model
                payload["model"] = FALLBACK_MODEL
                resp2 = requests.post(
                    OPENROUTER_API_URL,
                    headers=headers,
                    json=payload,
                    timeout=60
                )
                data2 = resp2.json()
                if "choices" in data2:
                    return data2["choices"][0]["message"][
                        "content"
                    ]
            return "AI service temporarily unavailable."
        except Exception as e:
            return f"Connection error: {str(e)}"

    def _offline_response(self, messages):
        """Fallback when no API key configured."""
        last = messages[-1]["content"]
        return (
            "⚠️ AI Agent requires OpenRouter API key.\n\n"
            "Get your free key at: "
            "https://openrouter.ai/keys\n\n"
            "Add to .env file:\n"
            "OPENROUTER_API_KEY=sk-or-v1-..."
        )

    def analyze_findings(self, findings, target,
                         scan_type="web"):
        """
        AI analyzes scan findings and provides
        deep security insights.
        """
        if not findings:
            return "No findings to analyze."

        # Build findings summary
        findings_text = ""
        for i, f in enumerate(findings[:20], 1):
            sev  = f.get("severity", "INFO")
            code = f.get("code", f.get("title", ""))
            msg  = f.get("message", f.get("description", ""))
            # Strip HTML tags
            msg = re.sub(r'<[^>]+>', '', msg)
            findings_text += (
                f"\n{i}. [{sev}] {code}\n"
                f"   {msg[:300]}\n"
            )

        prompt = f"""
I ran a {scan_type} security scan on: {target}
Found {len(findings)} vulnerabilities:
{findings_text}

Please provide:
1. EXECUTIVE SUMMARY (2-3 sentences for a manager)
2. CRITICAL RISK ANALYSIS (what can be attacked right now)
3. ATTACK CHAIN (how an attacker would chain these vulns)
4. TOP 3 FIXES (most impactful, prioritized)
5. COMPLIANCE IMPACT (GDPR, PCI-DSS, ISO 27001)
"""
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt}
        ]
        return self._call_api(messages)

    def analyze_code_file(self, code_content,
                          filename, language=None):
        """
        Deep code vulnerability analysis.
        Returns findings + optional fix.
        """
        # Detect language
        if not language:
            ext = filename.split(".")[-1].lower()
            lang_map = {
                "py":   "Python",
                "php":  "PHP",
                "js":   "JavaScript",
                "ts":   "TypeScript",
                "java": "Java",
                "cs":   "C#",
                "rb":   "Ruby",
                "go":   "Go",
                "cpp":  "C++",
                "c":    "C",
                "sql":  "SQL",
            }
            language = lang_map.get(ext, "Unknown")

        prompt = f"""
Analyze this {language} code file for security vulnerabilities.
Filename: {filename}
```{language.lower()}
{code_content[:8000]}
```

Provide a DETAILED security audit:

## VULNERABILITIES FOUND
For each vulnerability:
- Line number(s)
- Severity: CRITICAL/HIGH/MEDIUM/LOW
- Vulnerability type (CWE number)
- Description of the issue
- How an attacker would exploit it
- CVSS score estimate

## QUICK WINS
Security issues that can be fixed in < 5 minutes

## SECURITY SCORE
Rate this code 0-100 for security quality

## FIX RECOMMENDATION
Would you like me to fix this code?
I can provide a complete secured version.
"""
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt}
        ]
        result = self._call_api(
            messages, max_tokens=6000
        )
        # Store context for follow-up
        self.current_context = {
            "type":     "code",
            "filename": filename,
            "language": language,
            "content":  code_content,
            "analysis": result,
        }
        self.conversation_history = [
            {"role": "system",    "content": SYSTEM_PROMPT},
            {"role": "user",      "content": prompt},
            {"role": "assistant", "content": result},
        ]
        return result

    def fix_code(self, code_content=None,
                 filename=None, language=None,
                 specific_issue=None):
        """
        Generate a complete fixed version of the code.
        Returns the fixed file content.
        """
        # Use stored context if available
        if not code_content and self.current_context:
            code_content = self.current_context.get(
                "content", ""
            )
            filename = self.current_context.get(
                "filename", "file"
            )
            language = self.current_context.get(
                "language", "Unknown"
            )

        issue_context = ""
        if specific_issue:
            issue_context = (
                f"Focus on fixing: {specific_issue}\n"
            )

        prompt = f"""
{issue_context}
Please provide the COMPLETE FIXED version of this
{language} file with ALL security vulnerabilities resolved.

Original file: {filename}
```{language.lower() if language else ''}
{code_content[:8000]}
```

Requirements:
1. Fix ALL identified security issues
2. Add security comments for each fix
3. Do NOT break existing functionality
4. Follow OWASP secure coding guidelines
5. Use parameterized queries for SQL
6. Sanitize all user inputs
7. Add proper error handling
8. Return ONLY the complete fixed code

Wrap the fixed code in: ```fixed
[complete fixed code here]
```

After the code, list every change made with line refs.
"""
        if self.conversation_history:
            # Continue conversation
            self.conversation_history.append(
                {"role": "user", "content": prompt}
            )
            result = self._call_api(
                self.conversation_history,
                max_tokens=8000
            )
            self.conversation_history.append(
                {"role": "assistant", "content": result}
            )
        else:
            messages = [
                {"role": "system",
                 "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ]
            result = self._call_api(
                messages, max_tokens=8000
            )

        # Extract fixed code
        fixed_match = re.search(
            r'```fixed\n(.*?)\n```',
            result, re.DOTALL
        )
        if fixed_match:
            fixed_code = fixed_match.group(1)
        else:
            # Try generic code block
            code_match = re.search(
                r'```(?:\w+)?\n(.*?)\n```',
                result, re.DOTALL
            )
            fixed_code = (
                code_match.group(1)
                if code_match else None
            )

        return {
            "explanation": result,
            "fixed_code":  fixed_code,
            "filename":    filename,
            "language":    language,
        }

    def fix_apache_config(self, config_content,
                          findings):
        """
        Fix Apache misconfiguration automatically.
        Returns fixed httpd.conf content.
        """
        findings_text = "\n".join([
            f"- [{f.get('severity','')}] "
            f"{f.get('code','')}: "
            f"{re.sub(r'<[^>]+>', '', f.get('message',''))[:150]}"
            for f in findings[:15]
        ])

        prompt = f"""
Fix this Apache configuration file.
These misconfigurations were detected:
{findings_text}

Original Apache config:
```apache
{config_content[:6000]}
```

Provide the COMPLETE FIXED Apache configuration.
Fix ALL issues:
1. Replace deprecated Order/Allow/Deny with Require
2. Disable directory listing (Options -Indexes)
3. Add all missing security headers
4. Fix SSL/TLS to use TLSv1.2+ only
5. Add strong cipher suites
6. Set ServerTokens Prod + ServerSignature Off
7. Add TraceEnable Off
8. Set LimitRequestBody 10485760
9. Set Timeout 300
10. Fix ProxyPass placement (move outside Directory)
11. Fix all syntax errors
12. Add SymLinksIfOwnerMatch where needed

Wrap the fixed config in: ```fixed
[complete fixed apache config]
```
After the config, list every change with line refs.
"""
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt}
        ]
        result = self._call_api(
            messages, max_tokens=8000
        )
        fixed_match = re.search(
            r'```fixed\n(.*?)\n```',
            result, re.DOTALL
        )
        fixed_config = (
            fixed_match.group(1)
            if fixed_match else None
        )
        return {
            "explanation":  result,
            "fixed_config": fixed_config,
        }

    def chat(self, user_message, context=None):
        """
        General security chatbot.
        Maintains conversation history.
        """
        # Add context if provided
        if context and not self.conversation_history:
            ctx_msg = (
                f"Current scan context:\n"
                f"Target: {context.get('target','')}\n"
                f"Findings: "
                f"{context.get('total', 0)} issues\n"
                f"Risk: {context.get('risk','')}"
            )
            self.conversation_history = [
                {"role": "system",
                 "content": SYSTEM_PROMPT},
                {"role": "user",
                 "content": ctx_msg},
                {"role": "assistant",
                 "content": (
                     "I have reviewed the scan context. "
                     "I'm ready to help you analyze "
                     "and fix these security issues. "
                     "What would you like to know?"
                 )},
            ]

        if not self.conversation_history:
            self.conversation_history = [
                {"role": "system",
                 "content": SYSTEM_PROMPT}
            ]

        self.conversation_history.append(
            {"role": "user", "content": user_message}
        )
        response = self._call_api(
            self.conversation_history,
            max_tokens=2048
        )
        self.conversation_history.append(
            {"role": "assistant", "content": response}
        )
        return response

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
Network security assessment for: {target}
OS: {os_info.get('os', 'Unknown')}
Open ports: {ports_str}
Vulnerabilities found:
{findings_text}
Provide:

NETWORK ATTACK SURFACE ANALYSIS
How exposed is this host?
MOST DANGEROUS FINDINGS
What can be exploited right now?
ATTACK SCENARIOS
Step-by-step how an attacker exploits this
NETWORK HARDENING ROADMAP
Priority fixes with commands:

Firewall rules (iptables/ufw)
Service configuration changes
Patch recommendations


MONITORING RECOMMENDATIONS
What to log and alert on
"""
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt}
        ]
        return self._call_api(messages, max_tokens=4096)
        
    def reset_conversation(self):
        """Reset conversation history."""
        self.conversation_history = []
        self.current_context = {}
