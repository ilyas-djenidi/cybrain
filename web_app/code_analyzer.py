"""
CYBRAIN — Code File Vulnerability Analyzer
Static pattern analysis + AI deep analysis (Gemini)
PFE Master 2 — Information Security
NO AI in static scanning — AI only for deep analysis
"""

import re

# ── Static vulnerability patterns ──────────────────────────
# These run instantly with no AI
STATIC_PATTERNS = {
    "SQL Injection": {
        "severity": "CRITICAL",
        "cwe":      "CWE-89",
        "patterns": [
            r'execute\s*\(\s*["\'].*?\+',
            r'cursor\.execute\([^,)]*\+',
            r'f["\']SELECT.*?\{',
            r'mysqli_query.*?\$_',
            r'"SELECT.*?".*?\+',
            r'db\.query\s*\(\s*`.*?\$\{',
            r'\.query\s*\(\s*["\'].*?\+',
        ],
        "fix": (
            "Use parameterized queries only:\n"
            "Python: cursor.execute("
            "'SELECT * FROM t WHERE id=?', (uid,))\n"
            "PHP: $stmt->prepare('SELECT * FROM t "
            "WHERE id=?'); $stmt->bind_param('i',$id);"
        ),
    },
    "XSS (Cross-Site Scripting)": {
        "severity": "HIGH",
        "cwe":      "CWE-79",
        "patterns": [
            r'innerHTML\s*=',
            r'document\.write\s*\(',
            r'eval\s*\(',
            r'echo\s+\$_',
            r'print\s+\$_',
            r'Response\.Write.*?Request\.',
            r'\.html\s*\(.*?\$',
        ],
        "fix": (
            "Encode ALL user output:\n"
            "Python: markupsafe.escape(user_input)\n"
            "JS: element.textContent = input\n"
            "PHP: htmlspecialchars($in, ENT_QUOTES)"
        ),
    },
    "Hardcoded Credentials": {
        "severity": "CRITICAL",
        "cwe":      "CWE-798",
        "patterns": [
            r'password\s*=\s*["\'][^"\']{4,}["\']',
            r'passwd\s*=\s*["\'][^"\']{4,}["\']',
            r'secret\s*=\s*["\'][^"\']{8,}["\']',
            r'api_key\s*=\s*["\'][^"\']{8,}["\']',
            r'apikey\s*=\s*["\'][^"\']{8,}["\']',
            r'AWS_SECRET.*?=.*?["\'][^"\']+["\']',
            r'private_key\s*=\s*["\']',
        ],
        "fix": (
            "Use environment variables:\n"
            "Python: os.environ.get('DB_PASSWORD')\n"
            "Store in .env — never commit to git"
        ),
    },
    "Path Traversal": {
        "severity": "HIGH",
        "cwe":      "CWE-22",
        "patterns": [
            r'open\s*\([^)]*\$_',
            r'file_get_contents\s*\(\s*\$_',
            r'include\s*\(\s*\$_',
            r'require\s*\(\s*\$_',
            r'readFile\s*\(.*?req\.',
            r'open\s*\(.*?request\.',
            r'send\s*\(.*?req\.params',
        ],
        "fix": (
            "Validate file paths strictly:\n"
            "Use os.path.basename() to strip traversal\n"
            "Validate against allowlist of safe paths"
        ),
    },
    "Command Injection": {
        "severity": "CRITICAL",
        "cwe":      "CWE-78",
        "patterns": [
            r'os\.system\s*\(',
            r'subprocess\.call.*?shell=True',
            r'subprocess\.run.*?shell=True',
            r'subprocess\.Popen.*?shell=True',
            r'exec\s*\(\s*\$_',
            r'shell_exec\s*\(\s*\$_',
            r'passthru\s*\(\s*\$_',
        ],
        "fix": (
            "Never pass user input to shell:\n"
            "Python: subprocess.run(['cmd', arg], "
            "shell=False)\n"
            "Validate input with strict whitelist"
        ),
    },
    "Insecure Deserialization": {
        "severity": "CRITICAL",
        "cwe":      "CWE-502",
        "patterns": [
            r'pickle\.loads?\s*\(',
            r'yaml\.load\s*\([^)]*(?!Loader)',
            r'unserialize\s*\(',
            r'ObjectInputStream',
            r'BinaryFormatter',
            r'Marshal\.load',
        ],
        "fix": (
            "Use safe deserializers:\n"
            "Python: yaml.safe_load() not yaml.load()\n"
            "Avoid pickle for untrusted data\n"
            "Use JSON for data exchange"
        ),
    },
    "Weak Cryptography": {
        "severity": "HIGH",
        "cwe":      "CWE-327",
        "patterns": [
            r'hashlib\.md5',
            r'hashlib\.sha1\b',
            r'createHash\s*\(["\']md5',
            r'createHash\s*\(["\']sha1',
            r'DES\.',
            r'RC4\.',
        ],
        "fix": (
            "Use strong cryptography:\n"
            "Passwords: bcrypt or argon2\n"
            "Hashing: hashlib.sha256()\n"
            "Never use MD5 or SHA-1 for security"
        ),
    },
    "SSRF Risk": {
        "severity": "HIGH",
        "cwe":      "CWE-918",
        "patterns": [
            r'requests\.get\s*\(.*?request\.',
            r'requests\.get\s*\(.*?input',
            r'urllib\.request\.urlopen\s*\(.*?input',
            r'file_get_contents\s*\(\s*\$_GET',
            r'fetch\s*\(.*?req\.query',
            r'fetch\s*\(.*?req\.body',
        ],
        "fix": (
            "Validate URLs against strict allowlist:\n"
            "Never fetch URLs from user input\n"
            "Block requests to 127.0.0.1/169.254.x.x"
        ),
    },
    "Debug Mode Enabled": {
        "severity": "MEDIUM",
        "cwe":      "CWE-489",
        "patterns": [
            r'DEBUG\s*=\s*True',
            r'app\.run\s*\(.*?debug\s*=\s*True',
            r'development\s*:\s*true',
        ],
        "fix": (
            "Disable debug in production:\n"
            "Python: DEBUG = False\n"
            "Flask: app.run(debug=False)\n"
            "Use environment variables for config"
        ),
    },
    "Open Redirect": {
        "severity": "MEDIUM",
        "cwe":      "CWE-601",
        "patterns": [
            r'redirect\s*\(\s*request\.',
            r'header\s*\(\s*["\']Location.*?\$_',
            r'res\.redirect\s*\(.*?req\.',
            r'window\.location\s*=\s*.*?param',
        ],
        "fix": (
            "Validate redirect URLs:\n"
            "Use allowlist of permitted redirect targets\n"
            "Never redirect to user-supplied external URLs"
        ),
    },
    "JWT Issues": {
        "severity": "HIGH",
        "cwe":      "CWE-347",
        "patterns": [
            r'jwt\.decode\s*\(.*?verify.*?false',
            r'verify\s*:\s*false',
            r'algorithms\s*=\s*\[\s*["\']none["\']',
            r'alg.*?none',
        ],
        "fix": (
            "Always verify JWT signatures:\n"
            "Never use alg:none\n"
            "Use RS256 for public APIs\n"
            "Maintain strict algorithm whitelist"
        ),
    },
}


class CodeAnalyzer:
    """
    Code vulnerability analyzer.
    Static analysis runs instantly — no AI.
    AI deep analysis runs after static scan.
    """

    def __init__(self):
        # DO NOT import CybrainAgent here
        # Lazy load prevents crash if Gemini offline
        self._agent = None

    def _get_agent(self):
        """
        Lazy load AI agent.
        Only imports when actually needed.
        Returns None if AI unavailable (does NOT crash).
        """
        if self._agent is not None:
            return self._agent
        try:
            from ai_agent import CybrainAgent
            self._agent = CybrainAgent()
            return self._agent
        except Exception as e:
            print(
                f"[CODE ANALYZER] AI agent "
                f"unavailable: {e}"
            )
            return None

    def analyze(self, content, filename,
                use_ai=True):
        """
        Full analysis pipeline:
          1. Static pattern scan (instant, no AI)
          2. AI deep analysis (Gemini, if available)
        """
        language = self._detect_language(filename)
        lines    = content.splitlines()

        # Phase 1 — Static (always runs)
        static = self._static_analysis(
            content, lines, filename
        )

        # Phase 2 — AI deep analysis (optional)
        ai_result = None
        if use_ai:
            try:
                agent = self._get_agent()
                if agent:
                    ai_result = agent.analyze_code_file(
                        content, filename, language
                    )
                else:
                    ai_result = (
                        "AI analysis unavailable. "
                        "Check GEMINI_API_KEY in .env"
                    )
            except Exception as e:
                ai_result = (
                    f"AI analysis error: {str(e)}"
                )

        return {
            "filename":        filename,
            "language":        language,
            "lines_of_code":   len(lines),
            "static_findings": static,
            "ai_analysis":     ai_result,
            "fix_supported":   language in [
                "Python", "PHP", "JavaScript",
                "TypeScript", "Java", "C#",
                "Apache Config",
            ],
            "ui_findings": self._format_for_ui(
                static, filename
            ),
        }

    def _detect_language(self, filename):
        """Detect programming language from extension."""
        ext = filename.split(".")[-1].lower()
        return {
            "py":       "Python",
            "php":      "PHP",
            "js":       "JavaScript",
            "ts":       "TypeScript",
            "jsx":      "JavaScript",
            "tsx":      "TypeScript",
            "java":     "Java",
            "cs":       "C#",
            "rb":       "Ruby",
            "go":       "Go",
            "cpp":      "C++",
            "c":        "C",
            "sql":      "SQL",
            "conf":     "Apache Config",
            "htaccess": "Apache Config",
        }.get(ext, "Unknown")

    def _static_analysis(self, content, lines,
                          filename):
        """
        Pure regex-based static analysis.
        No network calls. No AI. Runs in milliseconds.
        """
        findings = []

        for vuln_name, info in STATIC_PATTERNS.items():
            for pattern in info["patterns"]:
                for i, line in enumerate(lines, 1):
                    try:
                        if re.search(
                            pattern, line,
                            re.IGNORECASE
                        ):
                            findings.append({
                                "severity":  info["severity"],
                                "title":     vuln_name,
                                "line":      i,
                                "code_line": line.strip()[:200],
                                "cwe":       info["cwe"],
                                "fix":       info["fix"],
                            })
                            break  # One match per pattern
                    except Exception:
                        pass  # Skip bad regex safely

        # Sort by severity
        order = {
            "CRITICAL": 0, "HIGH":   1,
            "MEDIUM":   2, "LOW":    3
        }
        findings.sort(
            key=lambda f: order.get(
                f.get("severity", "LOW"), 9
            )
        )
        return findings

    def _format_for_ui(self, findings, filename):
        """Format findings for React UI display."""
        return [{
            "severity": f["severity"],
            "line":     str(f["line"]),
            "message":  (
                f"<strong>{f['title']}</strong> "
                f"detected at line {f['line']}."
                "\n\n"
                "<strong>Vulnerable code:</strong>"
                "<br>"
                f"<code>{f['code_line']}</code>"
                "\n\n"
                "<strong>Recommendation:</strong>"
                "<br>"
                f"{f['fix']}"
                "\n\n"
                "<strong>CWE:</strong> "
                f"<a href='https://cwe.mitre.org/"
                f"data/definitions/"
                f"{f['cwe'].replace('CWE-','')}'"
                f" target='_blank'>{f['cwe']}</a>"
            ),
            "code": f["title"],
            "file": filename,
        } for f in findings]

    def fix_code(self, content, filename,
                 findings=None):
        """
        Generate fixed version of code using AI.
        Returns None for fixed_code if AI unavailable.
        """
        try:
            agent = self._get_agent()
            if agent:
                return agent.fix_code(
                    content, filename
                )
        except Exception as e:
            print(f"[CODE ANALYZER] Fix error: {e}")

        return {
            "explanation": (
                "AI fix unavailable. "
                "Check GEMINI_API_KEY in .env file."
            ),
            "fixed_code": None,
            "filename":   filename,
        }
